//go:build freebsd

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

// TestM3sCapEnterLeavesAmbientAFINET documents the FreeBSD residual: after
// CapEnter, AF_INET socket/connect remains possible (UnexpectedAllow). Jail
// ip-disable is not used in product children because it conflicts with
// allow-root CapRightsLimit.
func TestM3sCapEnterLeavesAmbientAFINET(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	role := authority.RoleApply
	before := confine.NegativeRoleNet(role)
	if before.Status != confine.StatusUnexpectedAllow {
		t.Fatalf("expected ambient allow before CapEnter, got %+v", before)
	}
	r := confine.ApplyEngineering(role)
	if err := r.RequireApplyAvailable(); err != nil {
		t.Fatal(err)
	}
	after := confine.NegativeRoleNet(role)
	if after.Status != confine.StatusUnexpectedAllow {
		t.Fatalf("expected CapEnter residual UnexpectedAllow, got %+v", after)
	}
}
