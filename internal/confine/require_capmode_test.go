package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireCapModeFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-CAP-MODE", Status: confine.StatusAvailable, Detail: "ok",
	}
	if err := confine.RequireCapModeFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-CAP-MODE", Status: confine.StatusSkipped, Detail: "nocap",
	}
	if err := confine.RequireCapModeFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-CAP-MODE", Status: confine.StatusUnexpectedAllow, Detail: "ambient",
	}
	if err := confine.RequireCapModeFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	unavail := confine.Finding{
		ID: "NEG-CAP-MODE", Status: confine.StatusUnavailable, Detail: "err",
	}
	if err := confine.RequireCapModeFinding(unavail); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "NEG-FS-OPEN", Status: confine.StatusAvailable}
	if err := confine.RequireCapModeFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestRequireCapModeAvailableNonFreeBSD(t *testing.T) {
	if runtime.GOOS == "freebsd" {
		t.Skip("FreeBSD asserts CapEnter separately")
	}
	if err := confine.RequireCapModeAvailable(); err != nil {
		t.Fatal(err)
	}
}
