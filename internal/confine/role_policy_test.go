package confine_test

import (
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
