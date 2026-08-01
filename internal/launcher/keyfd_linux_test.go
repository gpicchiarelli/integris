//go:build linux

package launcher_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
)

func TestCreateKeyFDSealedAgainstWrite(t *testing.T) {
	f, kind, err := launcher.CreateKeyFD(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if kind != launcher.KeyTransportMemfd {
		t.Fatalf("got %q", kind)
	}
	_, err = f.Write([]byte("x"))
	if err == nil {
		t.Fatal("expected write to fail on sealed memfd")
	}
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE | unix.F_SEAL_SEAL
	if seals&want != want {
		t.Fatalf("seals %#x missing %#x", seals, want)
	}
}
