//go:build freebsd

package launcher_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
)

// FreeBSD amd64/arm64 x/sys zerrors omit F_*_SEALS; keep local mirrors of
// fcntl.h (same values as keyfd_freebsd.go).
const (
	fGetSeals   = 20
	fSealSeal   = 0x1
	fSealShrink = 0x2
	fSealGrow   = 0x4
	fSealWrite  = 0x8
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
	seals, err := unix.FcntlInt(f.Fd(), fGetSeals, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := fSealShrink | fSealGrow | fSealWrite | fSealSeal
	if seals&want != want {
		t.Fatalf("seals %#x missing %#x", seals, want)
	}
}
