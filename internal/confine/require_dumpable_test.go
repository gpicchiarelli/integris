package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireDumpableFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-DUMPABLE", Status: confine.StatusAvailable, Detail: "clear",
	}
	if err := confine.RequireDumpableFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-DUMPABLE", Status: confine.StatusSkipped, Detail: "nolinux",
	}
	if err := confine.RequireDumpableFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-DUMPABLE", Status: confine.StatusUnexpectedAllow, Detail: "set",
	}
	if err := confine.RequireDumpableFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	unavail := confine.Finding{
		ID: "NEG-DUMPABLE", Status: confine.StatusUnavailable, Detail: "err",
	}
	if err := confine.RequireDumpableFinding(unavail); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "NEG-NO-NEW-PRIVS", Status: confine.StatusAvailable}
	if err := confine.RequireDumpableFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestRequireDumpableClearNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux covered by apply subprocess test")
	}
	if err := confine.RequireDumpableClear(); err != nil {
		t.Fatal(err)
	}
	f := confine.NegativeDumpable()
	if f.Status != confine.StatusSkipped {
		t.Fatalf("%+v", f)
	}
}
