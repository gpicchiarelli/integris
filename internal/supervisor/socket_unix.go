//go:build unix

package supervisor

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/ipc"
)

// SocketEndpoint is one side of an OS socketpair carrying authenticated IPC.
type SocketEndpoint struct {
	Local  authority.ProcessRole
	Remote authority.ProcessRole
	Conn   *net.UnixConn
	File   *os.File // optional; reserved for future ExtraFiles conferral
	Chan   *ipc.ChannelState
}

// SocketFabric holds OS-backed duplex endpoints for every mutual IPC edge.
// It does not spawn processes (Go profile prohibits os/exec in product code).
type SocketFabric struct {
	Plan  Plan
	Nonce [16]byte
	ends  map[Endpoint]*SocketEndpoint
}

// OpenSocketFabric creates socketpairs and authenticated channel state for each
// mutual IPC edge. Callers must Close the fabric.
func OpenSocketFabric(p Plan, rootKey []byte, nonce [16]byte) (*SocketFabric, error) {
	if err := p.ValidateIPCGraph(); err != nil {
		return nil, err
	}
	if len(rootKey) < 16 {
		return nil, fail("key", "root key must be at least 16 bytes")
	}
	// Collect unordered pairs (same as OpenFabric).
	type pair struct{ lo, hi authority.ProcessRole }
	seen := map[pair]struct{}{}
	var pairs []pair
	for _, c := range p.Children {
		for _, peer := range c.IPCPeers {
			pk, err := makePair(c.Role, peer)
			if err != nil {
				return nil, err
			}
			pr := pair{lo: pk.Lo, hi: pk.Hi}
			if _, ok := seen[pr]; ok {
				continue
			}
			seen[pr] = struct{}{}
			pairs = append(pairs, pr)
		}
	}
	fab := &SocketFabric{
		Plan:  p,
		Nonce: nonce,
		ends:  make(map[Endpoint]*SocketEndpoint, len(pairs)*2),
	}
	for _, pr := range pairs {
		if err := fab.installPair(pr.lo, pr.hi, rootKey); err != nil {
			fab.Close()
			return nil, err
		}
	}
	return fab, nil
}

// installPair creates a fresh socketpair and channel state for lo↔hi.
func (f *SocketFabric) installPair(lo, hi authority.ProcessRole, rootKey []byte) error {
	macKey, err := crypto.ChannelMACKey(rootKey, string(lo), string(hi))
	if err != nil {
		return fail("key", err.Error())
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fail("socket", err.Error())
	}
	f0 := os.NewFile(uintptr(fds[0]), fmt.Sprintf("ipc:%s-%s:a", lo, hi))
	f1 := os.NewFile(uintptr(fds[1]), fmt.Sprintf("ipc:%s-%s:b", lo, hi))
	c0, err := net.FileConn(f0)
	if err != nil {
		_ = f0.Close()
		_ = f1.Close()
		return fail("socket", err.Error())
	}
	c1, err := net.FileConn(f1)
	if err != nil {
		_ = c0.Close()
		_ = f0.Close()
		_ = f1.Close()
		return fail("socket", err.Error())
	}
	_ = f0.Close()
	_ = f1.Close()
	u0, ok0 := c0.(*net.UnixConn)
	u1, ok1 := c1.(*net.UnixConn)
	if !ok0 || !ok1 {
		_ = c0.Close()
		_ = c1.Close()
		return fail("socket", "not unix conn")
	}
	left, err := ipc.NewAuthenticatedChannel(lo, hi, f.Nonce, macKey)
	if err != nil {
		_ = u0.Close()
		_ = u1.Close()
		return fail("ipc", err.Error())
	}
	right, err := ipc.NewAuthenticatedChannel(hi, lo, f.Nonce, macKey)
	if err != nil {
		_ = u0.Close()
		_ = u1.Close()
		return fail("ipc", err.Error())
	}
	l, r := left, right
	f.ends[Endpoint{Local: lo, Remote: hi}] = &SocketEndpoint{
		Local: lo, Remote: hi, Conn: u0, Chan: &l,
	}
	f.ends[Endpoint{Local: hi, Remote: lo}] = &SocketEndpoint{
		Local: hi, Remote: lo, Conn: u1, Chan: &r,
	}
	return nil
}

// ReplacePair closes any existing endpoints for the unordered role edge and
// installs a fresh socketpair with new authenticated channel state. Required
// before RestartChild after StartChild consumed the child-side connection.
func (f *SocketFabric) ReplacePair(a, b authority.ProcessRole, rootKey []byte) error {
	if f == nil || f.ends == nil {
		return fail("fabric", "nil fabric")
	}
	pk, err := makePair(a, b)
	if err != nil {
		return err
	}
	for _, ep := range []*SocketEndpoint{
		f.ends[Endpoint{Local: pk.Lo, Remote: pk.Hi}],
		f.ends[Endpoint{Local: pk.Hi, Remote: pk.Lo}],
	} {
		if ep == nil {
			continue
		}
		if ep.Conn != nil {
			_ = ep.Conn.Close()
			ep.Conn = nil
		}
		if ep.File != nil {
			_ = ep.File.Close()
			ep.File = nil
		}
	}
	delete(f.ends, Endpoint{Local: pk.Lo, Remote: pk.Hi})
	delete(f.ends, Endpoint{Local: pk.Hi, Remote: pk.Lo})
	return f.installPair(pk.Lo, pk.Hi, rootKey)
}

// Endpoint returns the socket endpoint for local→remote.
func (f *SocketFabric) Endpoint(local, remote authority.ProcessRole) (*SocketEndpoint, error) {
	if f == nil {
		return nil, fail("fabric", "nil fabric")
	}
	ep, ok := f.ends[Endpoint{Local: local, Remote: remote}]
	if !ok {
		return nil, fail("missing", fmt.Sprintf("no socket %s→%s", local, remote))
	}
	return ep, nil
}

// Deliver encodes on sender, writes the framed bytes, and decodes on receiver.
func (f *SocketFabric) Deliver(sender, receiver authority.ProcessRole, typ ipc.MessageType, payload []byte) (ipc.Frame, error) {
	var zero ipc.Frame
	src, err := f.Endpoint(sender, receiver)
	if err != nil {
		return zero, err
	}
	dst, err := f.Endpoint(receiver, sender)
	if err != nil {
		return zero, err
	}
	raw, err := src.Chan.Encode(typ, payload)
	if err != nil {
		return zero, err
	}
	if err := ipc.WriteFrame(src.Conn, raw); err != nil {
		return zero, err
	}
	got, err := ipc.ReadFrame(dst.Conn, 0)
	if err != nil {
		return zero, err
	}
	return dst.Chan.Decode(got)
}

// PairCount returns unordered socketpair count.
func (f *SocketFabric) PairCount() int {
	if f == nil {
		return 0
	}
	return len(f.ends) / 2
}

// Close closes all connections.
func (f *SocketFabric) Close() error {
	if f == nil {
		return nil
	}
	var first error
	for _, ep := range f.ends {
		if ep.Conn != nil {
			if err := ep.Conn.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	f.ends = nil
	return first
}
