package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestRequireRlimitCoreFinding(t *testing.T) {
	ok := confine.Finding{
		ID: "NEG-RLIMIT-CORE", Status: confine.StatusAvailable, Detail: "zero",
	}
	if err := confine.RequireRlimitCoreFinding(ok); err != nil {
		t.Fatal(err)
	}

	skip := confine.Finding{
		ID: "NEG-RLIMIT-CORE", Status: confine.StatusSkipped, Detail: "nolinux",
	}
	if err := confine.RequireRlimitCoreFinding(skip); err != nil {
		t.Fatal(err)
	}

	bad := confine.Finding{
		ID: "NEG-RLIMIT-CORE", Status: confine.StatusUnexpectedAllow, Detail: "nonzero",
	}
	if err := confine.RequireRlimitCoreFinding(bad); err == nil {
		t.Fatal("expected unexpected_allow refusal")
	}

	unavail := confine.Finding{
		ID: "NEG-RLIMIT-CORE", Status: confine.StatusUnavailable, Detail: "err",
	}
	if err := confine.RequireRlimitCoreFinding(unavail); err == nil {
		t.Fatal("expected unavailable refusal")
	}

	wrong := confine.Finding{ID: "NEG-DUMPABLE", Status: confine.StatusAvailable}
	if err := confine.RequireRlimitCoreFinding(wrong); err == nil {
		t.Fatal("expected wrong-id refusal")
	}
}

func TestRequireRlimitCoreZeroNonUnix(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd":
		t.Skip("unix covered by setrlimit / apply subprocess tests")
	}
	if err := confine.RequireRlimitCoreZero(); err != nil {
		t.Fatal(err)
	}
	f := confine.NegativeRlimitCore()
	if f.Status != confine.StatusSkipped {
		t.Fatalf("%+v", f)
	}
}
