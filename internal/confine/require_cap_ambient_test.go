package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireCapAmbientFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-CAP-AMBIENT", Status: confine.StatusAvailable, Detail: "empty",
	}
	if err := confine.RequireCapAmbientFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-CAP-AMBIENT", Status: confine.StatusSkipped, Detail: "nolinux",
	}
	if err := confine.RequireCapAmbientFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-CAP-AMBIENT", Status: confine.StatusUnexpectedAllow, Detail: "caps",
	}
	if err := confine.RequireCapAmbientFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	unavail := confine.Finding{
		ID: "NEG-CAP-AMBIENT", Status: confine.StatusUnavailable, Detail: "err",
	}
	if err := confine.RequireCapAmbientFinding(unavail); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "NEG-CAP-MODE", Status: confine.StatusAvailable}
	if err := confine.RequireCapAmbientFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestRequireCapAmbientEmptyNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux covered by apply subprocess test")
	}
	if err := confine.RequireCapAmbientEmpty(); err != nil {
		t.Fatal(err)
	}
	f := confine.NegativeCapAmbient()
	if f.Status != confine.StatusSkipped {
		t.Fatalf("%+v", f)
	}
}
