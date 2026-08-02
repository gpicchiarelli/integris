//go:build unix

package ipc

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// KeyFDMagic is the unauthenticated bootstrap payload for SCM_RIGHTS key
// conferral. It must not collide with FrameMagic (INTIPC01).
var KeyFDMagic = []byte{'I', 'K', 'F', 'D'}

// PeerFDMagic is the unauthenticated payload for SCM_RIGHTS peer-IPC rebind
// (M2n). Distinct from KeyFDMagic so a hold child cannot confuse key vs peer.
// When ExtraPeer is set, this magic targets the ExtraPeer data-plane slot.
var PeerFDMagic = []byte{'I', 'P', 'E', 'R'}

// PrimaryPeerFDMagic rebinds the primary peer IPC end while ExtraPeer is set
// (M2w: net primary→auth). Distinct from PeerFDMagic so one KeyChannel can
// demux ExtraPeer vs primary without corrupting the data plane.
var PrimaryPeerFDMagic = []byte{'I', 'P', 'R', 'I'}

// StubReadyMagic is written by hold-mode stubs on the key channel after the
// first IPC exchange so the parent can synchronize before RestartOne.
var StubReadyMagic = []byte{'R', 'D', 'Y', '1'}

// RebindKind discriminates ExtraPeer vs primary peer FD messages on a key channel.
type RebindKind int

const (
	// RebindExtra is PeerFDMagic (ExtraPeer or sole primary when no ExtraPeer).
	RebindExtra RebindKind = iota
	// RebindPrimary is PrimaryPeerFDMagic (primary while ExtraPeer is set).
	RebindPrimary
)

// SendFD sends exactly one file descriptor over a Unix stream connection.
// The data payload is KeyFDMagic; it is not MAC-protected (chicken-egg).
func SendFD(conn *net.UnixConn, file *os.File) error {
	return sendFDConn(conn, file, KeyFDMagic)
}

// RecvFD receives exactly one file descriptor from a Unix stream connection.
func RecvFD(conn *net.UnixConn) (*os.File, error) {
	return recvFDConn(conn, KeyFDMagic, "integris-mac-key")
}

// RecvFDFile receives one file descriptor from an inherited *os.File socket
// (engineering child ExtraFiles path).
func RecvFDFile(sock *os.File) (*os.File, error) {
	return recvFDFileMagic(sock, KeyFDMagic, "integris-mac-key")
}

// SendFDFile sends one file descriptor over an *os.File Unix socket.
func SendFDFile(sock, file *os.File) error {
	return sendFDFileMagic(sock, file, KeyFDMagic)
}

// SendPeerFDFile confers a replacement peer IPC socket (M2n rebind).
func SendPeerFDFile(sock, file *os.File) error {
	return sendFDFileMagic(sock, file, PeerFDMagic)
}

// RecvPeerFDFile receives a replacement peer IPC socket (M2n rebind).
func RecvPeerFDFile(sock *os.File) (*os.File, error) {
	return recvFDFileMagic(sock, PeerFDMagic, "integris-peer-ipc")
}

// SendPrimaryPeerFDFile confers a replacement primary peer IPC socket (M2w).
func SendPrimaryPeerFDFile(sock, file *os.File) error {
	return sendFDFileMagic(sock, file, PrimaryPeerFDMagic)
}

// RecvRebindFDFile receives ExtraPeer or primary peer FD (PeerFDMagic /
// PrimaryPeerFDMagic) from a survivor KeyChannel.
func RecvRebindFDFile(sock *os.File) (*os.File, RebindKind, error) {
	if sock == nil {
		return nil, 0, fail("rights", "nil sock", true)
	}
	buf := make([]byte, len(PeerFDMagic))
	oob := make([]byte, unix.CmsgSpace(4))
	var n, oobn int
	var err error
	rc, e := sock.SyscallConn()
	if e != nil {
		return nil, 0, fail("rights", e.Error(), true)
	}
	cerr := rc.Read(func(fd uintptr) bool {
		n, oobn, _, _, err = unix.Recvmsg(int(fd), buf, oob, 0)
		return true
	})
	if cerr != nil {
		return nil, 0, fail("rights", cerr.Error(), true)
	}
	if err != nil {
		return nil, 0, fail("rights", err.Error(), true)
	}
	data := buf[:n]
	var kind RebindKind
	var magic []byte
	var name string
	switch {
	case len(data) == len(PeerFDMagic) && string(data) == string(PeerFDMagic):
		kind = RebindExtra
		magic = PeerFDMagic
		name = "integris-peer-ipc"
	case len(data) == len(PrimaryPeerFDMagic) && string(data) == string(PrimaryPeerFDMagic):
		kind = RebindPrimary
		magic = PrimaryPeerFDMagic
		name = "integris-primary-peer-ipc"
	default:
		return nil, 0, fail("rights", "bad rebind-fd magic", true)
	}
	f, err := parseRightsMessage(data, oob[:oobn], magic, name)
	if err != nil {
		return nil, 0, err
	}
	return f, kind, nil
}

func sendFDConn(conn *net.UnixConn, file *os.File, magic []byte) error {
	if conn == nil || file == nil {
		return fail("rights", "nil conn or file", true)
	}
	oob := unix.UnixRights(int(file.Fd()))
	n, oobn, err := conn.WriteMsgUnix(magic, oob, nil)
	if err != nil {
		return fail("rights", err.Error(), true)
	}
	if n != len(magic) || oobn != len(oob) {
		return fail("rights", fmt.Sprintf("short send n=%d oobn=%d", n, oobn), true)
	}
	return nil
}

func recvFDConn(conn *net.UnixConn, magic []byte, name string) (*os.File, error) {
	if conn == nil {
		return nil, fail("rights", "nil conn", true)
	}
	buf := make([]byte, len(magic))
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, fail("rights", err.Error(), true)
	}
	return parseRightsMessage(buf[:n], oob[:oobn], magic, name)
}

func recvFDFileMagic(sock *os.File, magic []byte, name string) (*os.File, error) {
	if sock == nil {
		return nil, fail("rights", "nil sock", true)
	}
	buf := make([]byte, len(magic))
	oob := make([]byte, unix.CmsgSpace(4))
	var n, oobn int
	var err error
	rc, e := sock.SyscallConn()
	if e != nil {
		return nil, fail("rights", e.Error(), true)
	}
	cerr := rc.Read(func(fd uintptr) bool {
		n, oobn, _, _, err = unix.Recvmsg(int(fd), buf, oob, 0)
		return true
	})
	if cerr != nil {
		return nil, fail("rights", cerr.Error(), true)
	}
	if err != nil {
		return nil, fail("rights", err.Error(), true)
	}
	return parseRightsMessage(buf[:n], oob[:oobn], magic, name)
}

func sendFDFileMagic(sock, file *os.File, magic []byte) error {
	if sock == nil || file == nil {
		return fail("rights", "nil sock or file", true)
	}
	oob := unix.UnixRights(int(file.Fd()))
	var err error
	rc, e := sock.SyscallConn()
	if e != nil {
		return fail("rights", e.Error(), true)
	}
	cerr := rc.Write(func(fd uintptr) bool {
		err = unix.Sendmsg(int(fd), magic, oob, nil, 0)
		return true
	})
	if cerr != nil {
		return fail("rights", cerr.Error(), true)
	}
	if err != nil {
		return fail("rights", err.Error(), true)
	}
	return nil
}

func parseRightsMessage(data, oob, magic []byte, name string) (*os.File, error) {
	if len(data) != len(magic) || string(data) != string(magic) {
		return nil, fail("rights", "bad rights-fd magic", true)
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fail("rights", err.Error(), true)
	}
	if len(msgs) != 1 {
		return nil, fail("rights", fmt.Sprintf("expected 1 cmsg got %d", len(msgs)), true)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil {
		return nil, fail("rights", err.Error(), true)
	}
	if len(fds) != 1 {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		return nil, fail("rights", fmt.Sprintf("expected 1 fd got %d", len(fds)), true)
	}
	unix.CloseOnExec(fds[0])
	f := os.NewFile(uintptr(fds[0]), name)
	if f == nil {
		_ = unix.Close(fds[0])
		return nil, fail("rights", "NewFile failed", true)
	}
	return f, nil
}
