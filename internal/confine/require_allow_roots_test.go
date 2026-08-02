package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireAllowRootLimitFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "APPLY-CAP-ALLOW-ROOTS", Status: confine.StatusAvailable, Detail: "ok",
	}
	if err := confine.RequireAllowRootLimitFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "APPLY-CAP-ALLOW-ROOTS", Status: confine.StatusSkipped, Detail: "nofds",
	}
	if err := confine.RequireAllowRootLimitFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "APPLY-CAP-ALLOW-ROOTS", Status: confine.StatusUnavailable, Detail: "limit failed",
	}
	if err := confine.RequireAllowRootLimitFinding(bad); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "APPLY-CAPSICUM", Status: confine.StatusAvailable}
	if err := confine.RequireAllowRootLimitFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestLimitAllowRootFDsSkippedOffFreeBSD(t *testing.T) {
	if runtime.GOOS == "freebsd" {
		t.Skip("FreeBSD exercises LimitAllowRootFDs separately")
	}
	f := confine.LimitAllowRootFDs(confine.ArchiveFSReadWrite)
	if err := confine.RequireAllowRootLimitFinding(f); err != nil {
		t.Fatal(err)
	}
}
