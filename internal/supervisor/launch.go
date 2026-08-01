package supervisor

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/crypto"
)

// DescriptorKind names a conferred object slot (no OS fd yet).
type DescriptorKind string

const (
	DescIPCEndpoint     DescriptorKind = "ipc_endpoint"
	DescArchiveRoot     DescriptorKind = "archive_root"
	DescStagingRoot     DescriptorKind = "staging_root"
	DescQuarantineRoot  DescriptorKind = "quarantine_root"
	DescJournalSegment  DescriptorKind = "journal_segment"
	DescReadonlyJournal DescriptorKind = "readonly_journal"
	DescEventSink       DescriptorKind = "event_sink"
	DescPolicyIdentity  DescriptorKind = "policy_identity"
)

// DescriptorSlot is a typed placeholder the supervisor will open and pass.
// Paths and raw fds are intentionally absent until OS spawn exists.
type DescriptorSlot struct {
	Kind  DescriptorKind
	Peer  authority.ProcessRole // set for DescIPCEndpoint
	Label string                // opaque slot id; never a filesystem path
}

// PeerKeyRef commits to a derived channel MAC key without retaining the key.
type PeerKeyRef struct {
	Peer  authority.ProcessRole
	KeyID codec.Digest // SHA-256(macKey)
}

// ChildLaunch is one child's sealed launch token (M2 prelude).
type ChildLaunch struct {
	Role         authority.ProcessRole
	Confer       []authority.Capability
	Slots        []DescriptorSlot
	Peers        []PeerKeyRef
	SessionNonce [16]byte
	Seal         codec.Digest // HMAC-SHA256(root, canonical) truncated to Digest
}

// LaunchSet is the supervisor's complete sealed child inventory.
type LaunchSet struct {
	Children     []ChildLaunch
	SessionNonce [16]byte
	PlanDigest   codec.Digest
}

// MaterializeLaunch builds sealed child tokens from a Plan. It opens no OS
// descriptors and does not spawn processes.
func MaterializeLaunch(p Plan, rootKey []byte, nonce [16]byte) (LaunchSet, error) {
	var zero LaunchSet
	if err := p.ValidateIPCGraph(); err != nil {
		return zero, err
	}
	if len(rootKey) < 16 {
		return zero, fail("key", "root key must be at least 16 bytes")
	}
	planDig := planDigest(p)
	out := make([]ChildLaunch, 0, len(p.Children))
	for _, c := range p.Children {
		slots := defaultSlots(c.Role, c.IPCPeers)
		peers := make([]PeerKeyRef, 0, len(c.IPCPeers))
		for _, peer := range c.IPCPeers {
			macKey, err := crypto.ChannelMACKey(rootKey, string(c.Role), string(peer))
			if err != nil {
				return zero, fail("key", err.Error())
			}
			peers = append(peers, PeerKeyRef{Peer: peer, KeyID: codec.SHA256(macKey)})
		}
		sort.Slice(peers, func(i, j int) bool { return peers[i].Peer < peers[j].Peer })
		cl := ChildLaunch{
			Role:         c.Role,
			Confer:       append([]authority.Capability{}, c.Confer...),
			Slots:        slots,
			Peers:        peers,
			SessionNonce: nonce,
		}
		seal, err := sealChild(rootKey, planDig, cl)
		if err != nil {
			return zero, err
		}
		cl.Seal = seal
		out = append(out, cl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return LaunchSet{Children: out, SessionNonce: nonce, PlanDigest: planDig}, nil
}

// Verify checks the seal against rootKey and expected plan digest.
func (c ChildLaunch) Verify(rootKey []byte, planDig codec.Digest) error {
	want, err := sealChild(rootKey, planDig, c)
	if err != nil {
		return err
	}
	if want != c.Seal {
		return fail("seal", "child launch seal mismatch")
	}
	return nil
}

// VerifyAll verifies every child seal in the set.
func (s LaunchSet) VerifyAll(rootKey []byte) error {
	for _, c := range s.Children {
		if err := c.Verify(rootKey, s.PlanDigest); err != nil {
			return err
		}
	}
	return nil
}

func sealChild(rootKey []byte, planDig codec.Digest, c ChildLaunch) (codec.Digest, error) {
	raw := encodeChildCanonical(planDig, c)
	mac := crypto.HMACSHA256(rootKey, raw)
	var d codec.Digest
	copy(d[:], mac)
	return d, nil
}

func encodeChildCanonical(planDig codec.Digest, c ChildLaunch) []byte {
	// Seal field is excluded from the preimage.
	buf := make([]byte, 0, 256)
	buf = appendU16String(buf, string(c.Role))
	buf = append(buf, planDig[:]...)
	buf = append(buf, c.SessionNonce[:]...)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(c.Confer)))
	buf = append(buf, tmp[:]...)
	for _, cap := range c.Confer {
		buf = appendU16String(buf, string(cap))
	}
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(c.Slots)))
	buf = append(buf, tmp[:]...)
	for _, s := range c.Slots {
		buf = appendU16String(buf, string(s.Kind))
		buf = appendU16String(buf, string(s.Peer))
		buf = appendU16String(buf, s.Label)
	}
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(c.Peers)))
	buf = append(buf, tmp[:]...)
	for _, p := range c.Peers {
		buf = appendU16String(buf, string(p.Peer))
		buf = append(buf, p.KeyID[:]...)
	}
	return buf
}

func appendU16String(buf []byte, s string) []byte {
	if len(s) > 65535 {
		s = s[:65535]
	}
	var tmp [2]byte
	codec.PutU16LE(tmp[:], uint16(len(s)))
	buf = append(buf, tmp[:]...)
	return append(buf, s...)
}

func planDigest(p Plan) codec.Digest {
	tr := crypto.NewTranscript()
	_ = tr.Append("launch-plan-v1", nil)
	for _, c := range p.Children {
		_ = tr.Append("role", []byte(c.Role))
		for _, cap := range c.Confer {
			_ = tr.Append("cap", []byte(cap))
		}
		for _, peer := range c.IPCPeers {
			_ = tr.Append("peer", []byte(peer))
		}
	}
	return tr.Digest()
}

func defaultSlots(role authority.ProcessRole, peers []authority.ProcessRole) []DescriptorSlot {
	var slots []DescriptorSlot
	for _, peer := range peers {
		slots = append(slots, DescriptorSlot{
			Kind: DescIPCEndpoint, Peer: peer,
			Label: fmt.Sprintf("ipc:%s:%s", role, peer),
		})
	}
	switch role {
	case authority.RoleSupervisor:
		slots = append(slots, DescriptorSlot{Kind: DescPolicyIdentity, Label: "policy"})
	case authority.RoleApply:
		slots = append(slots,
			DescriptorSlot{Kind: DescArchiveRoot, Label: "archive"},
			DescriptorSlot{Kind: DescStagingRoot, Label: "staging"},
			DescriptorSlot{Kind: DescQuarantineRoot, Label: "quarantine"},
		)
	case authority.RoleJournal:
		slots = append(slots, DescriptorSlot{Kind: DescJournalSegment, Label: "journal"})
	case authority.RoleAudit:
		slots = append(slots,
			DescriptorSlot{Kind: DescReadonlyJournal, Label: "journal-ro"},
			DescriptorSlot{Kind: DescEventSink, Label: "events"},
		)
	case authority.RoleIndex:
		slots = append(slots, DescriptorSlot{Kind: DescArchiveRoot, Label: "archive-ro"})
	}
	sort.Slice(slots, func(i, j int) bool {
		if slots[i].Kind != slots[j].Kind {
			return slots[i].Kind < slots[j].Kind
		}
		if slots[i].Peer != slots[j].Peer {
			return slots[i].Peer < slots[j].Peer
		}
		return slots[i].Label < slots[j].Label
	})
	return slots
}
