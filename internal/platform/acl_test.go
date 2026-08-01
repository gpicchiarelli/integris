package platform_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/platform"
)

func TestACLRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl-probe")
	if err := os.WriteFile(path, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := platform.ACLRoundTrip(path)
	if runtime.GOOS == "darwin" && platform.ACLSupported() {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if err == nil {
		t.Fatal("expected ACL unsupported error off Darwin+cgo")
	}
	if platform.ACLSupported() {
		t.Fatal("ACLSupported should be false here")
	}
}

func TestCopyACL(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := platform.CopyACL(dst, src)
	if runtime.GOOS == "darwin" && platform.ACLSupported() {
		if err != nil {
			t.Fatalf("no-ACL copy: %v", err)
		}
		if err := platform.ACLRoundTrip(src); err != nil {
			t.Fatal(err)
		}
		if err := platform.CopyACL(dst, src); err != nil {
			t.Fatalf("ACL copy: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("expected ACL unsupported error off Darwin+cgo")
	}
}
