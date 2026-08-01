//go:build linux

package platform_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/platform"
	"golang.org/x/sys/unix"
)

func TestLinuxACLRoundTripAndCopy(t *testing.T) {
	if !platform.ACLSupported() {
		t.Fatal("expected ACLSupported on Linux")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := platform.ACLRoundTrip(src); err != nil {
		if errIsACLUnsupportedFS(err) {
			t.Skipf("filesystem lacks POSIX ACL support: %v", err)
		}
		t.Fatal(err)
	}
	if err := platform.CopyACL(dst, src); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := unix.Getxattr(dst, "system.posix_acl_access", buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 {
		t.Fatalf("copied ACL too short: %d", n)
	}
}
