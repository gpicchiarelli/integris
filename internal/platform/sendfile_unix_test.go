//go:build unix && !openbsd

package platform_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/platform"
	"golang.org/x/sys/unix"
)

func TestSendFileSocketpair(t *testing.T) {
	if !platform.SendFileSupported() {
		t.Fatal("expected sendfile support on this port")
	}
	if platform.SendFileMechanism() != platform.SendFileMechanismSendfile {
		t.Fatalf("mechanism=%q", platform.SendFileMechanism())
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "blob")
	payload := []byte("sendfile-probe-payload-0123456789")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := os.NewFile(uintptr(fds[0]), "sendfile-w")
	r := os.NewFile(uintptr(fds[1]), "sendfile-r")
	defer w.Close()
	defer r.Close()

	done := make(chan []byte, 1)
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(r, buf); err != nil {
			errc <- err
			return
		}
		done <- buf
	}()

	written, newOff, err := platform.SendFile(w, in, 0, len(payload))
	if err != nil {
		t.Fatalf("SendFile: %v", err)
	}
	if written != len(payload) {
		t.Fatalf("written=%d want %d", written, len(payload))
	}
	if newOff != int64(len(payload)) {
		t.Fatalf("newOffset=%d want %d", newOff, len(payload))
	}

	select {
	case got := <-done:
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload mismatch: got %q want %q", got, payload)
		}
	case err := <-errc:
		t.Fatalf("read side: %v", err)
	}
}

func TestSendFileRejectsBadArgs(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "sf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, err := platform.SendFile(nil, f, 0, 1); err == nil {
		t.Fatal("expected nil out error")
	}
	if _, _, err := platform.SendFile(f, nil, 0, 1); err == nil {
		t.Fatal("expected nil in error")
	}
	if _, _, err := platform.SendFile(f, f, 0, 0); err == nil {
		t.Fatal("expected count=0 error")
	}
	if _, _, err := platform.SendFile(f, f, -1, 1); err == nil {
		t.Fatal("expected negative offset error")
	}
}
