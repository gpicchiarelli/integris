//go:build freebsd

package confine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireConferredLimitAfterLimit(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "pipe"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ok := confine.LimitConferredFDs(f)
	if ok.Status != confine.StatusAvailable {
		t.Fatalf("limit: %+v", ok)
	}
	if err := confine.RequireConferredLimitFinding(ok); err != nil {
		t.Fatal(err)
	}
}
