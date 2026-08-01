//go:build freebsd || openbsd

package platform

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// FreeBSD/OpenBSD x/sys does not export Darwin's UF_NODUMP. Exercise chflags
// round-trip with a cleared flags word so CopyBSDFlags still compiles and runs.
func TestCopyBSDFlagsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("f"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("f"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(src, 0); err != nil {
		t.Fatal(err)
	}
	if err := CopyBSDFlags(dst, src); err != nil {
		t.Fatal(err)
	}
}
