//go:build unix

package supervisor

import (
	"context"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

// Runtime is an engineering multi-child supervisor session: plan + socket fabric
// + sealed launch tokens + optional spawned role stubs.
type Runtime struct {
	Plan     Plan
	Launch   LaunchSet
	Fabric   *SocketFabric
	RootKey  []byte
	mu       sync.Mutex
	Children map[authority.ProcessRole]*launcher.Handle
	// KeyViaExtraFiles uses legacy ExtraFiles fd4 key conferral.
	// Default (false) uses SCM_RIGHTS after spawn.
	KeyViaExtraFiles bool
	// AllowRoots maps roles to absolute archive path allow-lists forwarded to
	// launcher/stub. StartChild / launcher.Start EvalSymlinks fail-closed (M5m).
	AllowRoots map[authority.ProcessRole][]string
	// StubMode maps roles to launcher stub IPC mode (respond/initiate).
	StubMode map[authority.ProcessRole]string
	// PairHold selects hold-initiate/hold-respond for StartPair (M2n RestartOne).
	PairHold bool
	// PushRootKey is conferred as a sealed FD (KeyViaExtraFiles) to PushRootRole
	// (RoleAuth for M2c, RoleNet for legacy M2a).
	PushRootKey  []byte
	PushRootRole authority.ProcessRole
	// ListenAddr / Once / ReadyPath configure RoleNet listen behaviour.
	ListenAddr string
	Once       bool
	ReadyPath  string
	// ExtraPeerFor maps a role to an additional IPC peer conferred at start
	// (M2c: net → apply while primary peer is auth).
	ExtraPeerFor map[authority.ProcessRole]authority.ProcessRole
	// ReleaseMode selects launcher ReleaseMode (M2k strict launch).
	ReleaseMode bool
}

// OpenRuntime builds launch tokens and a socket fabric. It does not spawn.
func OpenRuntime(p Plan, rootKey []byte, nonce [16]byte) (*Runtime, error) {
	set, err := MaterializeLaunch(p, rootKey, nonce)
	if err != nil {
		return nil, err
	}
	fab, err := OpenSocketFabric(p, rootKey, nonce)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		Plan:     p,
		Launch:   set,
		Fabric:   fab,
		RootKey:  append([]byte{}, rootKey...),
		Children: make(map[authority.ProcessRole]*launcher.Handle),
	}, nil
}

// Child returns the tracked handle for role.
func (r *Runtime) Child(role authority.ProcessRole) (*launcher.Handle, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.Children[role]
	return h, ok
}

// SetChild records a started child handle.
func (r *Runtime) SetChild(role authority.ProcessRole, h *launcher.Handle) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.Children[role] = h
	r.mu.Unlock()
}

// DeleteChild removes a tracked child without waiting.
func (r *Runtime) DeleteChild(role authority.ProcessRole) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.Children, role)
	r.mu.Unlock()
}

// DeleteChildIf removes role only when the current handle equals h.
func (r *Runtime) DeleteChildIf(role authority.ProcessRole, h *launcher.Handle) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.Children[role]; ok && cur == h {
		delete(r.Children, role)
		return true
	}
	return false
}

// ChildrenLen returns the number of tracked children.
func (r *Runtime) ChildrenLen() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Children)
}

// StartChild launches one role stub with the conferred peer socket for peer.
// executable must be absolute. EngineeringMode is the default; ReleaseMode
// selects fail-closed release-shaped launch (M2k).
func (r *Runtime) StartChild(ctx context.Context, role, peer authority.ProcessRole, executable string) error {
	if r == nil || r.Fabric == nil {
		return fail("runtime", "nil runtime")
	}
	r.mu.Lock()
	if _, ok := r.Children[role]; ok {
		r.mu.Unlock()
		return fail("runtime", "child already started: "+string(role))
	}
	r.mu.Unlock()
	ep, err := r.Fabric.Endpoint(role, peer)
	if err != nil {
		return err
	}
	sock, err := ep.Conn.File()
	if err != nil {
		return fail("socket", err.Error())
	}

	macKey, err := crypto.ChannelMACKey(r.RootKey, string(role), string(peer))
	if err != nil {
		_ = sock.Close()
		return fail("key", err.Error())
	}
	confer, slotKinds := r.childInventory(role)
	allowRoots, err := r.allowRootsFor(role)
	if err != nil {
		_ = sock.Close()
		return err
	}
	stubMode := r.stubModeFor(role)

	if r.KeyViaExtraFiles {
		_ = ep.Conn.Close()
		ep.Conn = nil
		req := launcher.Request{
			Executable:       executable,
			Role:             role,
			Peer:             peer,
			Nonce:            r.Fabric.Nonce,
			MACKey:           macKey,
			Socket:           sock,
			EngineeringMode:  !r.ReleaseMode,
			ReleaseMode:      r.ReleaseMode,
			KeyViaExtraFiles: true,
			Confer:           confer,
			SlotKinds:        slotKinds,
			AllowRoots:       allowRoots,
			StubMode:         stubMode,
		}
		req.Once = r.Once
		rootRole := r.PushRootRole
		if rootRole == "" {
			rootRole = authority.RoleNet // M2a legacy
		}
		if role == rootRole && len(r.PushRootKey) > 0 {
			req.RootKey = append([]byte{}, r.PushRootKey...)
		}
		if role == authority.RoleNet {
			req.ListenAddr = r.ListenAddr
			req.ReadyPath = r.ReadyPath
		}
		if extra, ok := r.ExtraPeerFor[role]; ok && extra != "" && extra != peer {
			extraEp, err := r.Fabric.Endpoint(role, extra)
			if err != nil {
				_ = sock.Close()
				return err
			}
			extraSock, err := extraEp.Conn.File()
			if err != nil {
				_ = sock.Close()
				return fail("socket", err.Error())
			}
			extraMAC, err := crypto.ChannelMACKey(r.RootKey, string(role), string(extra))
			if err != nil {
				_ = extraSock.Close()
				_ = sock.Close()
				return fail("key", err.Error())
			}
			_ = extraEp.Conn.Close()
			extraEp.Conn = nil
			req.ExtraPeer = extra
			req.ExtraSocket = extraSock
			req.ExtraMACKey = extraMAC
			h, err := launcher.Start(ctx, req)
			_ = sock.Close()
			_ = extraSock.Close()
			if err != nil {
				return err
			}
			r.SetChild(role, h)
			return nil
		}
		h, err := launcher.Start(ctx, req)
		_ = sock.Close()
		if err != nil {
			return err
		}
		r.SetChild(role, h)
		return nil
	}

	// M2l: sockets via ExtraFiles; keys via SCM_RIGHTS on a dedicated key
	// channel (Handle.KeyChannel). Avoids needing the peer fabric end, which
	// is already consumed when both roles are live children.
	_ = ep.Conn.Close()
	ep.Conn = nil

	req := launcher.Request{
		Executable:      executable,
		Role:            role,
		Peer:            peer,
		Nonce:           r.Fabric.Nonce,
		MACKey:          macKey,
		Socket:          sock,
		EngineeringMode: !r.ReleaseMode,
		ReleaseMode:     r.ReleaseMode,
		Confer:          confer,
		SlotKinds:       slotKinds,
		AllowRoots:      allowRoots,
		StubMode:        stubMode,
		Once:            r.Once,
	}
	rootRole := r.PushRootRole
	if rootRole == "" {
		rootRole = authority.RoleNet
	}
	if role == rootRole && len(r.PushRootKey) > 0 {
		req.RootKey = append([]byte{}, r.PushRootKey...)
	}
	if role == authority.RoleNet {
		req.ListenAddr = r.ListenAddr
		req.ReadyPath = r.ReadyPath
	}

	var extraSock *os.File
	if extra, ok := r.ExtraPeerFor[role]; ok && extra != "" && extra != peer {
		extraEp, err := r.Fabric.Endpoint(role, extra)
		if err != nil {
			_ = sock.Close()
			return err
		}
		extraSock, err = extraEp.Conn.File()
		if err != nil {
			_ = sock.Close()
			return fail("socket", err.Error())
		}
		extraMAC, err := crypto.ChannelMACKey(r.RootKey, string(role), string(extra))
		if err != nil {
			_ = extraSock.Close()
			_ = sock.Close()
			return fail("key", err.Error())
		}
		_ = extraEp.Conn.Close()
		extraEp.Conn = nil
		req.ExtraPeer = extra
		req.ExtraSocket = extraSock
		req.ExtraMACKey = extraMAC
	}

	h, err := launcher.Start(ctx, req)
	_ = sock.Close()
	if extraSock != nil {
		_ = extraSock.Close()
	}
	if err != nil {
		return err
	}
	if h.KeyFD == nil || h.KeyChannel == nil {
		closeSCMKeys(h)
		_ = h.Cmd.Process.Kill()
		return fail("key", "missing SCM key FD or channel")
	}
	// Order on key channel: MAC, optional root, optional extra-MAC.
	// Keep KeyChannel open on Handle for M2n peer-FD rebind (RestartOne).
	ch := h.KeyChannel
	if err := ipc.SendFDFile(ch, h.KeyFD); err != nil {
		_ = h.KeyFD.Close()
		closeSCMKeys(h)
		_ = h.Cmd.Process.Kill()
		return fail("rights", err.Error())
	}
	_ = h.KeyFD.Close()
	h.KeyFD = nil
	if h.RootKeyFD != nil {
		if err := ipc.SendFDFile(ch, h.RootKeyFD); err != nil {
			closeSCMKeys(h)
			_ = h.Cmd.Process.Kill()
			return fail("rights", err.Error())
		}
		_ = h.RootKeyFD.Close()
		h.RootKeyFD = nil
	}
	if h.ExtraKeyFD != nil {
		if err := ipc.SendFDFile(ch, h.ExtraKeyFD); err != nil {
			closeSCMKeys(h)
			_ = h.Cmd.Process.Kill()
			return fail("rights", err.Error())
		}
		_ = h.ExtraKeyFD.Close()
		h.ExtraKeyFD = nil
	}
	r.SetChild(role, h)
	return nil
}

func closeSCMKeys(h *launcher.Handle) {
	if h == nil {
		return
	}
	if h.KeyChannel != nil {
		_ = h.KeyChannel.Close()
		h.KeyChannel = nil
	}
	if h.KeyFD != nil {
		_ = h.KeyFD.Close()
		h.KeyFD = nil
	}
	if h.RootKeyFD != nil {
		_ = h.RootKeyFD.Close()
		h.RootKeyFD = nil
	}
	if h.ExtraKeyFD != nil {
		_ = h.ExtraKeyFD.Close()
		h.ExtraKeyFD = nil
	}
}

func (r *Runtime) allowRootsFor(role authority.ProcessRole) ([]string, error) {
	if r == nil || r.AllowRoots == nil {
		return nil, nil
	}
	roots := r.AllowRoots[role]
	if len(roots) == 0 {
		return nil, nil
	}
	norm, err := confine.NormalizeAllowRoots(roots)
	if err != nil {
		return nil, err
	}
	r.AllowRoots[role] = norm
	return append([]string{}, norm...), nil
}

func (r *Runtime) stubModeFor(role authority.ProcessRole) string {
	if r == nil || r.StubMode == nil {
		return launcher.StubModeRespond
	}
	if m := r.StubMode[role]; m != "" {
		return m
	}
	return launcher.StubModeRespond
}

func (r *Runtime) childInventory(role authority.ProcessRole) ([]authority.Capability, []string) {
	for _, c := range r.Launch.Children {
		if c.Role == role {
			return append([]authority.Capability{}, c.Confer...), SlotKinds(c.Slots)
		}
	}
	return nil, nil
}

// WaitChild waits for a started child.
func (r *Runtime) WaitChild(role authority.ProcessRole) error {
	r.mu.Lock()
	h, ok := r.Children[role]
	if !ok {
		r.mu.Unlock()
		return fail("runtime", "unknown child "+string(role))
	}
	r.mu.Unlock()
	err := h.Wait()
	r.mu.Lock()
	delete(r.Children, role)
	r.mu.Unlock()
	return err
}

// RestartChild kills any tracked instance of role, replaces the role↔peer
// socketpair (StartChild consumes the child end), and starts a fresh child.
// For dual-live edges use RestartPair or RestartOne (M2n in-place rebind).
func (r *Runtime) RestartChild(ctx context.Context, role, peer authority.ProcessRole, executable string) error {
	if r == nil || r.Fabric == nil {
		return fail("runtime", "nil runtime")
	}
	r.mu.Lock()
	h, ok := r.Children[role]
	if ok {
		delete(r.Children, role)
	}
	r.mu.Unlock()
	if ok {
		closeSCMKeys(h)
		if h != nil && h.Cmd != nil && h.Cmd.Process != nil {
			_ = h.Cmd.Process.Kill()
		}
		_ = h.Wait()
	}
	if err := r.Fabric.ReplacePair(role, peer, r.RootKey); err != nil {
		return err
	}
	return r.StartChild(ctx, role, peer, executable)
}

// StartPair launches both ends of an IPC edge as live children.
// M2m: works with default SCM key-channel conferral (each child has its own
// KeyChannel). Legacy KeyViaExtraFiles remains supported.
// initiator uses StubModeInitiate; the peer responds. Responder is started first.
func (r *Runtime) StartPair(ctx context.Context, a, b, initiator authority.ProcessRole, executable string) error {
	if r == nil || r.Fabric == nil {
		return fail("runtime", "nil runtime")
	}
	if initiator != a && initiator != b {
		return fail("runtime", "initiator must be one endpoint of the pair")
	}
	responder := a
	if initiator == a {
		responder = b
	}
	if r.StubMode == nil {
		r.StubMode = make(map[authority.ProcessRole]string)
	}
	if r.PairHold {
		r.StubMode[initiator] = launcher.StubModeHoldInitiate
		r.StubMode[responder] = launcher.StubModeHoldRespond
	} else {
		r.StubMode[initiator] = launcher.StubModeInitiate
		r.StubMode[responder] = launcher.StubModeRespond
	}
	if err := r.StartChild(ctx, responder, initiator, executable); err != nil {
		return err
	}
	if err := r.StartChild(ctx, initiator, responder, executable); err != nil {
		r.mu.Lock()
		h := r.Children[responder]
		delete(r.Children, responder)
		r.mu.Unlock()
		if h != nil && h.Cmd != nil && h.Cmd.Process != nil {
			_ = h.Cmd.Process.Kill()
			_ = h.Wait()
		}
		return err
	}
	return nil
}

// RestartPair kills both ends of an edge, replaces the socketpair, and StartPair.
func (r *Runtime) RestartPair(ctx context.Context, a, b, initiator authority.ProcessRole, executable string) error {
	if r == nil || r.Fabric == nil {
		return fail("runtime", "nil runtime")
	}
	for _, role := range []authority.ProcessRole{a, b} {
		r.mu.Lock()
		h, ok := r.Children[role]
		if ok {
			delete(r.Children, role)
		}
		r.mu.Unlock()
		if ok {
			closeSCMKeys(h)
			if h != nil && h.Cmd != nil && h.Cmd.Process != nil {
				_ = h.Cmd.Process.Kill()
			}
			_ = h.Wait()
		}
	}
	if err := r.Fabric.ReplacePair(a, b, r.RootKey); err != nil {
		return err
	}
	return r.StartPair(ctx, a, b, initiator, executable)
}

// WaitPairHoldReady blocks until hold-mode children write StubReadyMagic on
// their key channels (after the first IPC exchange). Used before RestartOne.
func (r *Runtime) WaitPairHoldReady(roles []authority.ProcessRole, timeout time.Duration) error {
	if r == nil {
		return fail("runtime", "nil runtime")
	}
	deadline := time.Now().Add(timeout)
	for _, role := range roles {
		r.mu.Lock()
		h, ok := r.Children[role]
		r.mu.Unlock()
		if !ok || h == nil || h.KeyChannel == nil {
			return fail("runtime", "missing KeyChannel for "+string(role))
		}
		_ = h.KeyChannel.SetReadDeadline(deadline)
		buf := make([]byte, len(ipc.StubReadyMagic))
		if _, err := io.ReadFull(h.KeyChannel, buf); err != nil {
			return fail("ready", string(role)+": "+err.Error())
		}
		if string(buf) != string(ipc.StubReadyMagic) {
			return fail("ready", "bad ready magic from "+string(role))
		}
		_ = h.KeyChannel.SetReadDeadline(time.Time{})
	}
	return nil
}

// RestartOne replaces a failed dual-live endpoint while the survivor keeps its
// PID (M2n). Requires the SCM key-channel path: survivor Handle.KeyChannel must
// still be open (child hold modes keep the channel for peer-FD recv).
// Flow: kill dead → ReplacePair → StartChild(dead) → SendPeerFDFile to live.
func (r *Runtime) RestartOne(ctx context.Context, dead, live, initiator authority.ProcessRole, executable string) error {
	if r == nil || r.Fabric == nil {
		return fail("runtime", "nil runtime")
	}
	if dead == live {
		return fail("runtime", "dead and live must differ")
	}
	if initiator != dead && initiator != live {
		return fail("runtime", "initiator must be dead or live")
	}
	if r.KeyViaExtraFiles {
		return fail("runtime", "RestartOne requires SCM key-channel path")
	}
	r.mu.Lock()
	liveH, ok := r.Children[live]
	if !ok || liveH == nil || liveH.KeyChannel == nil {
		r.mu.Unlock()
		return fail("runtime", "live child missing open KeyChannel")
	}
	if liveH.Cmd == nil || liveH.Cmd.Process == nil {
		r.mu.Unlock()
		return fail("runtime", "live child has no process")
	}
	livePID := liveH.Cmd.Process.Pid
	deadH, deadOk := r.Children[dead]
	if deadOk {
		delete(r.Children, dead)
	}
	r.mu.Unlock()

	if deadOk {
		closeSCMKeys(deadH)
		if deadH != nil && deadH.Cmd != nil && deadH.Cmd.Process != nil {
			_ = deadH.Cmd.Process.Kill()
		}
		_ = deadH.Wait()
	}
	if err := r.Fabric.ReplacePair(dead, live, r.RootKey); err != nil {
		return err
	}
	if r.StubMode == nil {
		r.StubMode = make(map[authority.ProcessRole]string)
	}
	// Respawned child does a single exchange; survivor hold mode does the peer
	// after RecvPeerFDFile.
	if dead == initiator {
		r.StubMode[dead] = launcher.StubModeInitiate
	} else {
		r.StubMode[dead] = launcher.StubModeRespond
	}
	if err := r.StartChild(ctx, dead, live, executable); err != nil {
		return err
	}
	ep, err := r.Fabric.Endpoint(live, dead)
	if err != nil {
		return err
	}
	peerSock, err := ep.Conn.File()
	if err != nil {
		return fail("socket", err.Error())
	}
	_ = ep.Conn.Close()
	ep.Conn = nil
	if err := ipc.SendPeerFDFile(liveH.KeyChannel, peerSock); err != nil {
		_ = peerSock.Close()
		return fail("rights", err.Error())
	}
	_ = peerSock.Close()
	// Survivor PID must be unchanged.
	if liveH.Cmd.Process.Pid != livePID {
		return fail("runtime", "live PID changed during RestartOne")
	}
	return nil
}

// Close kills any tracked children and closes the fabric.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	var first error
	r.mu.Lock()
	roles := make([]authority.ProcessRole, 0, len(r.Children))
	handles := make(map[authority.ProcessRole]*launcher.Handle, len(r.Children))
	for role, h := range r.Children {
		roles = append(roles, role)
		handles[role] = h
	}
	r.Children = make(map[authority.ProcessRole]*launcher.Handle)
	r.mu.Unlock()
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	for _, role := range roles {
		if h := handles[role]; h != nil {
			closeSCMKeys(h)
			if h.Cmd != nil && h.Cmd.Process != nil {
				_ = h.Cmd.Process.Kill()
				_ = h.Wait()
			}
		}
	}
	if r.Fabric != nil {
		if err := r.Fabric.Close(); err != nil && first == nil {
			first = err
		}
		r.Fabric = nil
	}
	return first
}

// ChildRoles returns started roles in sorted order.
func (r *Runtime) ChildRoles() []authority.ProcessRole {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	out := make([]authority.ProcessRole, 0, len(r.Children))
	for role := range r.Children {
		out = append(out, role)
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
