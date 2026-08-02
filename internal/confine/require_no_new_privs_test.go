package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireNoNewPrivsFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-NO-NEW-PRIVS", Status: confine.StatusAvailable, Detail: "set",
	}
	if err := confine.RequireNoNewPrivsFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-NO-NEW-PRIVS", Status: confine.StatusSkipped, Detail: "nolinux",
	}
	if err := confine.RequireNoNewPrivsFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-NO-NEW-PRIVS", Status: confine.StatusUnexpectedAllow, Detail: "unset",
	}
	if err := confine.RequireNoNewPrivsFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	unavail := confine.Finding{
		ID: "NEG-NO-NEW-PRIVS", Status: confine.StatusUnavailable, Detail: "err",
	}
	if err := confine.RequireNoNewPrivsFinding(unavail); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "NEG-CAP-AMBIENT", Status: confine.StatusAvailable}
	if err := confine.RequireNoNewPrivsFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestRequireNoNewPrivsSetNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux covered by apply subprocess test")
	}
	if err := confine.RequireNoNewPrivsSet(); err != nil {
		t.Fatal(err)
	}
	f := confine.NegativeNoNewPrivs()
	if f.Status != confine.StatusSkipped {
		t.Fatalf("%+v", f)
	}
}
