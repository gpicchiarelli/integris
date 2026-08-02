//go:build freebsd

package confine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireAllowRootLimitAfterLimit(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Open(filepath.Clean(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	skip := confine.LimitAllowRootFDs(confine.ArchiveFSNone, f)
	if err := confine.RequireAllowRootLimitFinding(skip); err != nil {
		t.Fatal(err)
	}

	ok := confine.LimitAllowRootFDs(confine.ArchiveFSReadWrite, f)
	if ok.Status != confine.StatusAvailable {
		t.Fatalf("limit: %+v", ok)
	}
	if err := confine.RequireAllowRootLimitFinding(ok); err != nil {
		t.Fatal(err)
	}
}
