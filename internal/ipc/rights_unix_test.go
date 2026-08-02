//go:build unix

package ipc_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestSendRecvFDRoundTrip(t *testing.T) {
	a, b := mustUnixPair(t)
	defer a.Close()
	defer b.Close()

	key := bytes.Repeat([]byte{0x42}, 32)
	keyFD, _, err := launcher.CreateKeyFD(key)
	if err != nil {
		t.Fatal(err)
	}
	defer keyFD.Close()

	done := make(chan error, 1)
	go func() {
		f, err := ipc.RecvFD(b)
		if err != nil {
			done <- err
			return
		}
		defer f.Close()
		got, err := io.ReadAll(io.LimitReader(f, 257))
		if err != nil {
			done <- err
			return
		}
		if !bytes.Equal(got, key) {
			done <- fmt.Errorf("got %x want %x", got, key)
			return
		}
		done <- nil
	}()

	if err := ipc.SendFD(a, keyFD); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSendRecvFDFile(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "parent")
	child := os.NewFile(uintptr(fds[1]), "child")
	defer parent.Close()
	defer child.Close()

	key := bytes.Repeat([]byte{0x11}, 32)
	keyFD, _, err := launcher.CreateKeyFD(key)
	if err != nil {
		t.Fatal(err)
	}
	defer keyFD.Close()

	done := make(chan error, 1)
	go func() {
		f, err := ipc.RecvFDFile(child)
		if err != nil {
			done <- err
			return
		}
		defer f.Close()
		got, err := io.ReadAll(io.LimitReader(f, 257))
		if err != nil {
			done <- err
			return
		}
		if !bytes.Equal(got, key) {
			done <- fmt.Errorf("got %x want %x", got, key)
			return
		}
		done <- nil
	}()

	if err := ipc.SendFDFile(parent, keyFD); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSendRecvPeerFDFile(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "parent")
	child := os.NewFile(uintptr(fds[1]), "child")
	defer parent.Close()
	defer child.Close()

	peerFds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer := os.NewFile(uintptr(peerFds[0]), "peer")
	defer peer.Close()
	_ = os.NewFile(uintptr(peerFds[1]), "peer-other").Close()

	done := make(chan error, 1)
	go func() {
		f, err := ipc.RecvPeerFDFile(child)
		if err != nil {
			done <- err
			return
		}
		_ = f.Close()
		done <- nil
	}()
	if err := ipc.SendPeerFDFile(parent, peer); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSendRecvPrimaryPeerFDFileDemux(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "parent")
	child := os.NewFile(uintptr(fds[1]), "child")
	defer parent.Close()
	defer child.Close()

	mkPeer := func() *os.File {
		t.Helper()
		p, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = os.NewFile(uintptr(p[1]), "peer-other").Close()
		return os.NewFile(uintptr(p[0]), "peer")
	}
	extra := mkPeer()
	defer extra.Close()
	primary := mkPeer()
	defer primary.Close()

	done := make(chan error, 1)
	go func() {
		f1, k1, err := ipc.RecvRebindFDFile(child)
		if err != nil {
			done <- err
			return
		}
		_ = f1.Close()
		if k1 != ipc.RebindExtra {
			done <- fmt.Errorf("want RebindExtra got %v", k1)
			return
		}
		f2, k2, err := ipc.RecvRebindFDFile(child)
		if err != nil {
			done <- err
			return
		}
		_ = f2.Close()
		if k2 != ipc.RebindPrimary {
			done <- fmt.Errorf("want RebindPrimary got %v", k2)
			return
		}
		done <- nil
	}()
	if err := ipc.SendPeerFDFile(parent, extra); err != nil {
		t.Fatal(err)
	}
	if err := ipc.SendPrimaryPeerFDFile(parent, primary); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func mustUnixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	f0 := os.NewFile(uintptr(fds[0]), "a")
	f1 := os.NewFile(uintptr(fds[1]), "b")
	c0, err := net.FileConn(f0)
	if err != nil {
		t.Fatal(err)
	}
	_ = f0.Close()
	c1, err := net.FileConn(f1)
	if err != nil {
		t.Fatal(err)
	}
	_ = f1.Close()
	return c0.(*net.UnixConn), c1.(*net.UnixConn)
}
