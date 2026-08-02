//go:build unix

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestSplitAllowRootsNormalizeSymlink(t *testing.T) {
	realDir := t.TempDir()
	parent := t.TempDir()
	link := filepath.Join(parent, "dest-link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	got, err := confine.NormalizeAllowRoots(splitAllowRoots(link))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v want [%q]", got, want)
	}
}

func TestSplitAllowRootsNormalizeRejectsRelative(t *testing.T) {
	if _, err := confine.NormalizeAllowRoots(splitAllowRoots("relative/root")); err == nil {
		t.Fatal("expected relative reject")
	}
}
