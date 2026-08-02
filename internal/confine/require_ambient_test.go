package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireAmbientFSReadFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-FS-READ", Status: confine.StatusDeniedExpected, Detail: "denied",
	}
	if err := confine.RequireAmbientFSReadFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-FS-READ", Status: confine.StatusSkipped, Detail: "nosupport",
	}
	if err := confine.RequireAmbientFSReadFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-FS-READ", Status: confine.StatusUnexpectedAllow, Detail: "ambient",
	}
	if err := confine.RequireAmbientFSReadFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	wrong := confine.Finding{ID: "NEG-FS-OPEN", Status: confine.StatusDeniedExpected}
	if err := confine.RequireAmbientFSReadFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}

	unavailable := confine.Finding{
		ID: "NEG-FS-READ", Status: confine.StatusUnavailable, Detail: "probe path missing: /etc/hosts",
	}
	if err := confine.RequireAmbientFSReadFinding(unavailable); err == nil {
		t.Fatal("expected unavailable refusal")
	}
}
