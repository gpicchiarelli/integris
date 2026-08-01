package confine_test

import (
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRoleMayHoldNetwork(t *testing.T) {
	if !confine.RoleMayHoldNetwork(authority.RoleNet) {
		t.Fatal("net role must hold network_sockets")
	}
	for _, role := range []authority.ProcessRole{
		authority.RoleParser,
		authority.RolePlan,
		authority.RoleJournal,
		authority.RoleAudit,
		authority.RoleIndex,
		authority.RoleApply,
		authority.RoleAuth,
		authority.RoleSupervisor,
		"",
		"unknown-role",
	} {
		if confine.RoleMayHoldNetwork(role) {
			t.Fatalf("%s must not hold network_sockets", role)
		}
	}
}

func TestRoleArchiveFSMode(t *testing.T) {
	if got := confine.RoleArchiveFSMode(authority.RoleApply); got != confine.ArchiveFSReadWrite {
		t.Fatalf("apply: %v", got)
	}
	if got := confine.RoleArchiveFSMode(authority.RoleIndex); got != confine.ArchiveFSReadonly {
		t.Fatalf("index: %v", got)
	}
	for _, role := range []authority.ProcessRole{
		authority.RoleParser, authority.RoleNet, authority.RolePlan, authority.RoleJournal,
	} {
		if got := confine.RoleArchiveFSMode(role); got != confine.ArchiveFSNone {
			t.Fatalf("%s: %v", role, got)
		}
	}
}

func TestNormalizeAllowRoots(t *testing.T) {
	dir := t.TempDir()
	got, err := confine.NormalizeAllowRoots([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%v", got)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != want {
		t.Fatalf("%q vs %q", got[0], want)
	}
	if _, err := confine.NormalizeAllowRoots([]string{"relative"}); err == nil {
		t.Fatal("expected relative reject")
	}
}
