package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireSeccompFilterFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-SECCOMP", Status: confine.StatusAvailable, Detail: "filter",
	}
	if err := confine.RequireSeccompFilterFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-SECCOMP", Status: confine.StatusSkipped, Detail: "nolinux",
	}
	if err := confine.RequireSeccompFilterFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-SECCOMP", Status: confine.StatusUnexpectedAllow, Detail: "unset",
	}
	if err := confine.RequireSeccompFilterFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	unavail := confine.Finding{
		ID: "NEG-SECCOMP", Status: confine.StatusUnavailable, Detail: "err",
	}
	if err := confine.RequireSeccompFilterFinding(unavail); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "NEG-NO-NEW-PRIVS", Status: confine.StatusAvailable}
	if err := confine.RequireSeccompFilterFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestRequireSeccompFilterNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux covered by apply subprocess test")
	}
	if err := confine.RequireSeccompFilter(); err != nil {
		t.Fatal(err)
	}
	f := confine.NegativeSeccompFilter()
	if f.Status != confine.StatusSkipped {
		t.Fatalf("%+v", f)
	}
}
