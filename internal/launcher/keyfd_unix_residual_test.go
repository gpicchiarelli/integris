//go:build unix && !linux && !freebsd

package launcher_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/launcher"
)

// TestM4cCreateKeyFDAnonUnlinkedResidual documents the Darwin/OpenBSD residual:
// CreateKeyFD uses an unlinked O_RDONLY temp file (KeyTransportAnonFile). There
// is no memfd_create / F_ADD_SEALS path on these platforms; write fails because
// the FD is read-only, not because seals were applied.
func TestM4cCreateKeyFDAnonUnlinkedResidual(t *testing.T) {
	f, kind, err := launcher.CreateKeyFD(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if kind != launcher.KeyTransportAnonFile {
		t.Fatalf("got transport %q, want %q (M4c residual)", kind, launcher.KeyTransportAnonFile)
	}
	_, err = f.Write([]byte("x"))
	if err == nil {
		t.Fatal("expected write to fail on O_RDONLY anon-unlinked key FD")
	}
}
