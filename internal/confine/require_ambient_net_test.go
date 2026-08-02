package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireAmbientRoleNetFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-ROLE-NET", Status: confine.StatusDeniedExpected, Detail: "denied",
	}
	if err := confine.RequireAmbientRoleNetFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-ROLE-NET", Status: confine.StatusSkipped, Detail: "nosupport",
	}
	if err := confine.RequireAmbientRoleNetFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-ROLE-NET", Status: confine.StatusUnexpectedAllow, Detail: "ambient",
	}
	if err := confine.RequireAmbientRoleNetFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	wrong := confine.Finding{ID: "NEG-FS-READ", Status: confine.StatusDeniedExpected}
	if err := confine.RequireAmbientRoleNetFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestRequireAmbientRoleNetDeniedFreeBSDNoop(t *testing.T) {
	if runtime.GOOS != "freebsd" {
		t.Skip("M3s residual: RequireAmbientRoleNetDenied is FreeBSD no-op only")
	}
	if err := confine.RequireAmbientRoleNetDenied(authority.RoleApply); err != nil {
		t.Fatal(err)
	}
}

func TestRequireAmbientRoleNetDeniedNetworkRoleSkipped(t *testing.T) {
	// CapNetwork holder → NEG-ROLE-NET Skipped without needing ApplyEngineering.
	if err := confine.RequireAmbientRoleNetDenied(authority.RoleNet); err != nil {
		t.Fatal(err)
	}
}
