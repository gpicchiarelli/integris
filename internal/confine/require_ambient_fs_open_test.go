package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireAmbientFSOpenFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-FS-OPEN", Status: confine.StatusDeniedExpected, Detail: "denied",
	}
	if err := confine.RequireAmbientFSOpenFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-FS-OPEN", Status: confine.StatusSkipped, Detail: "nosupport",
	}
	if err := confine.RequireAmbientFSOpenFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-FS-OPEN", Status: confine.StatusUnexpectedAllow, Detail: "ambient",
	}
	if err := confine.RequireAmbientFSOpenFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	wrong := confine.Finding{ID: "NEG-FS-READ", Status: confine.StatusDeniedExpected}
	if err := confine.RequireAmbientFSOpenFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}

	unavailable := confine.Finding{
		ID: "NEG-FS-OPEN", Status: confine.StatusUnavailable, Detail: "probe path exists",
	}
	if err := confine.RequireAmbientFSOpenFinding(unavailable); err == nil {
		t.Fatal("expected unavailable refusal")
	}
}
