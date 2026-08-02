//go:build linux || openbsd

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestRequireAmbientRoleNetDeniedAfterApply(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	role := authority.RoleApply
	r := confine.ApplyEngineering(role)
	if err := r.RequireApplyAvailable(); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireAmbientRoleNetDenied(role); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireAmbientRoleNetDenied(authority.RoleNet); err != nil {
		t.Fatal(err) // CapNetwork holder → Skipped
	}
}
