package supervisor

import (
	"fmt"
	"sort"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/ipc"
)

// pairKey is an unordered role pair with lexicographic ordering.
type pairKey struct {
	Lo authority.ProcessRole
	Hi authority.ProcessRole
}

func makePair(a, b authority.ProcessRole) (pairKey, error) {
	if a == "" || b == "" || a == b {
		return pairKey{}, fail("pair", "invalid peer pair")
	}
	if a < b {
		return pairKey{Lo: a, Hi: b}, nil
	}
	return pairKey{Lo: b, Hi: a}, nil
}

// Endpoint identifies one direction of an authenticated IPC channel.
type Endpoint struct {
	Local  authority.ProcessRole
	Remote authority.ProcessRole
}

// Fabric materializes authenticated in-process IPC channel endpoints from a
// validated Plan. It does not spawn OS processes.
type Fabric struct {
	Plan     Plan
	Nonce    [16]byte
	channels map[Endpoint]*ipc.ChannelState
}

// ValidateIPCGraph ensures every IPCPeers edge is mutual and both roles exist
// in the plan.
func (p Plan) ValidateIPCGraph() error {
	byRole := map[authority.ProcessRole]ChildSpec{}
	for _, c := range p.Children {
		byRole[c.Role] = c
	}
	for _, c := range p.Children {
		for _, peer := range c.IPCPeers {
			other, ok := byRole[peer]
			if !ok {
				return fail("ipc", fmt.Sprintf("%s peers missing role %s", c.Role, peer))
			}
			found := false
			for _, back := range other.IPCPeers {
				if back == c.Role {
					found = true
					break
				}
			}
			if !found {
				return fail("ipc", fmt.Sprintf("%s→%s is not mutual", c.Role, peer))
			}
		}
	}
	return nil
}

// OpenFabric derives per-pair MAC keys and opens dual channel endpoints for
// every mutual IPC edge. rootKey must be at least 16 bytes (provisional HKDF).
func OpenFabric(p Plan, rootKey []byte, nonce [16]byte) (Fabric, error) {
	var zero Fabric
	if err := p.ValidateIPCGraph(); err != nil {
		return zero, err
	}
	if len(rootKey) < 16 {
		return zero, fail("key", "root key must be at least 16 bytes")
	}
	pairs := map[pairKey]struct{}{}
	for _, c := range p.Children {
		for _, peer := range c.IPCPeers {
			pk, err := makePair(c.Role, peer)
			if err != nil {
				return zero, err
			}
			pairs[pk] = struct{}{}
		}
	}
	ordered := make([]pairKey, 0, len(pairs))
	for pk := range pairs {
		ordered = append(ordered, pk)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Lo != ordered[j].Lo {
			return ordered[i].Lo < ordered[j].Lo
		}
		return ordered[i].Hi < ordered[j].Hi
	})

	out := Fabric{
		Plan:     p,
		Nonce:    nonce,
		channels: make(map[Endpoint]*ipc.ChannelState, len(ordered)*2),
	}
	for _, pk := range ordered {
		macKey, err := crypto.ChannelMACKey(rootKey, string(pk.Lo), string(pk.Hi))
		if err != nil {
			return zero, fail("key", err.Error())
		}
		left, err := ipc.NewAuthenticatedChannel(pk.Lo, pk.Hi, nonce, macKey)
		if err != nil {
			return zero, fail("ipc", err.Error())
		}
		right, err := ipc.NewAuthenticatedChannel(pk.Hi, pk.Lo, nonce, macKey)
		if err != nil {
			return zero, fail("ipc", err.Error())
		}
		l, r := left, right
		out.channels[Endpoint{Local: pk.Lo, Remote: pk.Hi}] = &l
		out.channels[Endpoint{Local: pk.Hi, Remote: pk.Lo}] = &r
	}
	return out, nil
}

// Channel returns the mutable endpoint for local→remote, if present.
func (f *Fabric) Channel(local, remote authority.ProcessRole) (*ipc.ChannelState, error) {
	if f == nil {
		return nil, fail("fabric", "nil fabric")
	}
	ch, ok := f.channels[Endpoint{Local: local, Remote: remote}]
	if !ok {
		return nil, fail("missing", fmt.Sprintf("no channel %s→%s", local, remote))
	}
	return ch, nil
}

// PairCount returns the number of unordered IPC pairs.
func (f Fabric) PairCount() int {
	return len(f.channels) / 2
}

// Endpoints returns a stable-sorted list of directed endpoints.
func (f Fabric) Endpoints() []Endpoint {
	out := make([]Endpoint, 0, len(f.channels))
	for ep := range f.channels {
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Local != out[j].Local {
			return out[i].Local < out[j].Local
		}
		return out[i].Remote < out[j].Remote
	})
	return out
}

// Deliver encodes a frame on sender→receiver and decodes it on the peer endpoint.
func (f *Fabric) Deliver(sender, receiver authority.ProcessRole, typ ipc.MessageType, payload []byte) (ipc.Frame, error) {
	var zero ipc.Frame
	src, err := f.Channel(sender, receiver)
	if err != nil {
		return zero, err
	}
	dst, err := f.Channel(receiver, sender)
	if err != nil {
		return zero, err
	}
	raw, err := src.Encode(typ, payload)
	if err != nil {
		return zero, err
	}
	return dst.Decode(raw)
}
