//go:build unix

package supervisor

import (
	"context"
	"sort"

	"github.com/gpicchiarelli/integris/internal/authority"
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
	Children map[authority.ProcessRole]*launcher.Handle
	// KeyViaExtraFiles uses legacy ExtraFiles fd4 key conferral.
	// Default (false) uses SCM_RIGHTS after spawn.
	KeyViaExtraFiles bool
	// AllowRoots maps roles to absolute archive path allow-lists forwarded to
	// launcher/stub ApplyEngineeringOpts (EvalSymlinks in child).
	AllowRoots map[authority.ProcessRole][]string
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

// StartChild launches one role stub with the conferred peer socket for peer.
// executable must be absolute. EngineeringMode is forced true.
func (r *Runtime) StartChild(ctx context.Context, role, peer authority.ProcessRole, executable string) error {
	if r == nil || r.Fabric == nil {
		return fail("runtime", "nil runtime")
	}
	if _, ok := r.Children[role]; ok {
		return fail("runtime", "child already started: "+string(role))
	}
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
	allowRoots := r.allowRootsFor(role)

	if r.KeyViaExtraFiles {
		_ = ep.Conn.Close()
		ep.Conn = nil
		h, err := launcher.Start(ctx, launcher.Request{
			Executable:       executable,
			Role:             role,
			Peer:             peer,
			Nonce:            r.Fabric.Nonce,
			MACKey:           macKey,
			Socket:           sock,
			EngineeringMode:  true,
			KeyViaExtraFiles: true,
			Confer:           confer,
			SlotKinds:        slotKinds,
			AllowRoots:       allowRoots,
		})
		_ = sock.Close()
		if err != nil {
			return err
		}
		r.Children[role] = h
		return nil
	}

	parentEp, err := r.Fabric.Endpoint(peer, role)
	if err != nil {
		_ = sock.Close()
		return err
	}
	_ = ep.Conn.Close()
	ep.Conn = nil
	h, err := launcher.Start(ctx, launcher.Request{
		Executable:      executable,
		Role:            role,
		Peer:            peer,
		Nonce:           r.Fabric.Nonce,
		MACKey:          macKey,
		Socket:          sock,
		EngineeringMode: true,
		Confer:          confer,
		SlotKinds:       slotKinds,
		AllowRoots:      allowRoots,
	})
	_ = sock.Close()
	if err != nil {
		return err
	}
	if h.KeyFD == nil {
		_ = h.Cmd.Process.Kill()
		return fail("key", "missing SCM key FD")
	}
	if err := ipc.SendFD(parentEp.Conn, h.KeyFD); err != nil {
		_ = h.KeyFD.Close()
		_ = h.Cmd.Process.Kill()
		return fail("rights", err.Error())
	}
	_ = h.KeyFD.Close()
	h.KeyFD = nil
	r.Children[role] = h
	return nil
}

func (r *Runtime) allowRootsFor(role authority.ProcessRole) []string {
	if r == nil || r.AllowRoots == nil {
		return nil
	}
	roots := r.AllowRoots[role]
	if len(roots) == 0 {
		return nil
	}
	return append([]string{}, roots...)
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
	h, ok := r.Children[role]
	if !ok {
		return fail("runtime", "unknown child "+string(role))
	}
	err := h.Wait()
	delete(r.Children, role)
	return err
}

// RestartChild kills any tracked instance of role, replaces the role↔peer
// socketpair (StartChild consumes the child end), and starts a fresh child.
// Engineering-only: both ends of a live dual-child edge are not recovered here.
func (r *Runtime) RestartChild(ctx context.Context, role, peer authority.ProcessRole, executable string) error {
	if r == nil || r.Fabric == nil {
		return fail("runtime", "nil runtime")
	}
	if h, ok := r.Children[role]; ok {
		if h != nil && h.Cmd != nil && h.Cmd.Process != nil {
			_ = h.Cmd.Process.Kill()
		}
		_ = h.Wait()
		delete(r.Children, role)
	}
	if err := r.Fabric.ReplacePair(role, peer, r.RootKey); err != nil {
		return err
	}
	return r.StartChild(ctx, role, peer, executable)
}

// Close kills any tracked children and closes the fabric.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	var first error
	roles := make([]authority.ProcessRole, 0, len(r.Children))
	for role := range r.Children {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	for _, role := range roles {
		if h := r.Children[role]; h != nil && h.Cmd != nil && h.Cmd.Process != nil {
			_ = h.Cmd.Process.Kill()
			_ = h.Wait()
		}
		delete(r.Children, role)
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
	out := make([]authority.ProcessRole, 0, len(r.Children))
	for role := range r.Children {
		out = append(out, role)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
