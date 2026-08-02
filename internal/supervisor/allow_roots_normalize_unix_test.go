//go:build unix

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
)

func TestAllowRootsForNormalizeWriteBack(t *testing.T) {
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
	rt := &Runtime{
		AllowRoots: map[authority.ProcessRole][]string{
			authority.RoleApply: {link},
		},
	}
	got, err := rt.allowRootsFor(authority.RoleApply)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v want [%q]", got, want)
	}
	if rt.AllowRoots[authority.RoleApply][0] != want {
		t.Fatalf("write-back %v", rt.AllowRoots[authority.RoleApply])
	}
}

func TestAllowRootsForRefuseRelative(t *testing.T) {
	rt := &Runtime{
		AllowRoots: map[authority.ProcessRole][]string{
			authority.RoleApply: {"relative/root"},
		},
	}
	if _, err := rt.allowRootsFor(authority.RoleApply); err == nil {
		t.Fatal("expected relative reject")
	}
}
