//go:build freebsd

package confine_test

import (
	"os"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestRequireAmbientRoleNetDeniedAfterJailCapEnter(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("jail_set(2) for ip4/ip6=disable requires root")
	}
	role := authority.RoleApply
	if err := confine.RequireAmbientRoleNetDenied(role); err == nil {
		t.Fatal("expected refuse before jail+CapEnter")
	}
	r := confine.ApplyEngineering(role)
	if err := r.RequireApplyAvailable(); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireAmbientRoleNetDenied(role); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireAmbientRoleNetDenied(authority.RoleNet); err != nil {
		t.Fatal(err)
	}
}
