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
		macKey, err := crypto.ChannelMACKey(rootKey, string(pr.lo), string(pr.hi))
		if err != nil {
			fab.Close()
			return nil, fail("key", err.Error())
		}
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			fab.Close()
			return nil, fail("socket", err.Error())
		}
		f0 := os.NewFile(uintptr(fds[0]), fmt.Sprintf("ipc:%s-%s:a", pr.lo, pr.hi))
		f1 := os.NewFile(uintptr(fds[1]), fmt.Sprintf("ipc:%s-%s:b", pr.lo, pr.hi))
		c0, err := net.FileConn(f0)
		if err != nil {
			_ = f0.Close()
			_ = f1.Close()
			fab.Close()
			return nil, fail("socket", err.Error())
		}
		c1, err := net.FileConn(f1)
		if err != nil {
			_ = c0.Close()
			_ = f0.Close()
			_ = f1.Close()
			fab.Close()
			return nil, fail("socket", err.Error())
		}
		// FileConn duplicates the fd; close the originals to avoid leaks.
		_ = f0.Close()
		_ = f1.Close()
		u0, ok0 := c0.(*net.UnixConn)
		u1, ok1 := c1.(*net.UnixConn)
		if !ok0 || !ok1 {
			_ = c0.Close()
			_ = c1.Close()
			fab.Close()
			return nil, fail("socket", "not unix conn")
		}
		left, err := ipc.NewAuthenticatedChannel(pr.lo, pr.hi, nonce, macKey)
		if err != nil {
			_ = u0.Close()
			_ = u1.Close()
			fab.Close()
			return nil, fail("ipc", err.Error())
		}
		right, err := ipc.NewAuthenticatedChannel(pr.hi, pr.lo, nonce, macKey)
		if err != nil {
			_ = u0.Close()
			_ = u1.Close()
			fab.Close()
			return nil, fail("ipc", err.Error())
		}
		l, r := left, right
		// Retain conn only; File field nil (fd owned by UnixConn).
		fab.ends[Endpoint{Local: pr.lo, Remote: pr.hi}] = &SocketEndpoint{
			Local: pr.lo, Remote: pr.hi, Conn: u0, Chan: &l,
		}
		fab.ends[Endpoint{Local: pr.hi, Remote: pr.lo}] = &SocketEndpoint{
			Local: pr.hi, Remote: pr.lo, Conn: u1, Chan: &r,
		}
	}
	return fab, nil
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
