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

// SendFD sends exactly one file descriptor over a Unix stream connection.
// The data payload is KeyFDMagic; it is not MAC-protected (chicken-egg).
func SendFD(conn *net.UnixConn, file *os.File) error {
	if conn == nil || file == nil {
		return fail("rights", "nil conn or file", true)
	}
	oob := unix.UnixRights(int(file.Fd()))
	n, oobn, err := conn.WriteMsgUnix(KeyFDMagic, oob, nil)
	if err != nil {
		return fail("rights", err.Error(), true)
	}
	if n != len(KeyFDMagic) || oobn != len(oob) {
		return fail("rights", fmt.Sprintf("short send n=%d oobn=%d", n, oobn), true)
	}
	return nil
}

// RecvFD receives exactly one file descriptor from a Unix stream connection.
func RecvFD(conn *net.UnixConn) (*os.File, error) {
	if conn == nil {
		return nil, fail("rights", "nil conn", true)
	}
	buf := make([]byte, len(KeyFDMagic))
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, fail("rights", err.Error(), true)
	}
	return parseRightsMessage(buf[:n], oob[:oobn])
}

// RecvFDFile receives one file descriptor from an inherited *os.File socket
// (engineering child ExtraFiles path).
func RecvFDFile(sock *os.File) (*os.File, error) {
	if sock == nil {
		return nil, fail("rights", "nil sock", true)
	}
	buf := make([]byte, len(KeyFDMagic))
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
	return parseRightsMessage(buf[:n], oob[:oobn])
}

// SendFDFile sends one file descriptor over an *os.File Unix socket.
func SendFDFile(sock, file *os.File) error {
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
		err = unix.Sendmsg(int(fd), KeyFDMagic, oob, nil, 0)
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

func parseRightsMessage(data, oob []byte) (*os.File, error) {
	if len(data) != len(KeyFDMagic) || string(data) != string(KeyFDMagic) {
		return nil, fail("rights", "bad key-fd magic", true)
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
	f := os.NewFile(uintptr(fds[0]), "integris-mac-key")
	if f == nil {
		_ = unix.Close(fds[0])
		return nil, fail("rights", "NewFile failed", true)
	}
	return f, nil
}
