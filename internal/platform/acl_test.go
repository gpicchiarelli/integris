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
