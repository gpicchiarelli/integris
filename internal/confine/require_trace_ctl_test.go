package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireTraceCtlFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-TRACE-CTL", Status: confine.StatusAvailable, Detail: "disabled",
	}
	if err := confine.RequireTraceCtlFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-TRACE-CTL", Status: confine.StatusSkipped, Detail: "nofreebsd",
	}
	if err := confine.RequireTraceCtlFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-TRACE-CTL", Status: confine.StatusUnexpectedAllow, Detail: "enabled",
	}
	if err := confine.RequireTraceCtlFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	unavail := confine.Finding{
		ID: "NEG-TRACE-CTL", Status: confine.StatusUnavailable, Detail: "err",
	}
	if err := confine.RequireTraceCtlFinding(unavail); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "NEG-DUMPABLE", Status: confine.StatusAvailable}
	if err := confine.RequireTraceCtlFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestRequireTraceCtlDisabledNonFreeBSD(t *testing.T) {
	if runtime.GOOS == "freebsd" {
		t.Skip("freebsd covered by apply subprocess test")
	}
	if err := confine.RequireTraceCtlDisabled(); err != nil {
		t.Fatal(err)
	}
	f := confine.NegativeTraceCtl()
	if f.Status != confine.StatusSkipped {
		t.Fatalf("%+v", f)
	}
}
