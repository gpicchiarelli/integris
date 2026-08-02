package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireAmbientExecFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-EXEC", Status: confine.StatusDeniedExpected, Detail: "denied",
	}
	if err := confine.RequireAmbientExecFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-EXEC", Status: confine.StatusSkipped, Detail: "nosupport",
	}
	if err := confine.RequireAmbientExecFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-EXEC", Status: confine.StatusUnexpectedAllow, Detail: "ambient",
	}
	if err := confine.RequireAmbientExecFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	wrong := confine.Finding{ID: "NEG-FS-READ", Status: confine.StatusDeniedExpected}
	if err := confine.RequireAmbientExecFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}

	unavailable := confine.Finding{
		ID: "NEG-EXEC", Status: confine.StatusUnavailable, Detail: "probe failed",
	}
	if err := confine.RequireAmbientExecFinding(unavailable); err == nil {
		t.Fatal("expected unavailable refusal")
	}
}
