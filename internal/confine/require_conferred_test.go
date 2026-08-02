package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireConferredLimitFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "APPLY-CAP-RIGHTS", Status: confine.StatusAvailable, Detail: "ok",
	}
	if err := confine.RequireConferredLimitFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "APPLY-CAP-RIGHTS", Status: confine.StatusSkipped, Detail: "nocap",
	}
	if err := confine.RequireConferredLimitFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "APPLY-CAP-RIGHTS", Status: confine.StatusUnavailable, Detail: "limit failed",
	}
	if err := confine.RequireConferredLimitFinding(bad); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "APPLY-CAPSICUM", Status: confine.StatusAvailable}
	if err := confine.RequireConferredLimitFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestLimitConferredFDsSkippedOffFreeBSD(t *testing.T) {
	if runtime.GOOS == "freebsd" {
		t.Skip("FreeBSD exercises LimitConferredFDs separately")
	}
	f := confine.LimitConferredFDs()
	if err := confine.RequireConferredLimitFinding(f); err != nil {
		t.Fatal(err)
	}
}
