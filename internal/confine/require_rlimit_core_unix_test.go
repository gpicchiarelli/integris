//go:build unix

package confine_test

import (
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
)

func TestRequireRlimitCoreZeroAfterApply(t *testing.T) {
	if runtime.GOOS == "linux" && testing.CoverMode() != "" {
		// Landlock in this process blocks go cover meta writes under /tmp.
		t.Skip("Landlock apply blocks coverage meta under -cover")
	}
	if !launcher.InTestSubprocess(t) {
		return
	}
	r := confine.ApplyEngineering(authority.RoleApply)
	if err := r.RequireApplyAvailable(); err != nil {
		// Darwin CGO_ENABLED=0 leaves APPLY-SEATBELT Skipped — release refuses.
		if runtime.GOOS == "darwin" {
			var coreOK bool
			for _, f := range r.Findings {
				if f.ID == "APPLY-RLIMIT-CORE" && f.Status == confine.StatusAvailable {
					coreOK = true
				}
			}
			if !coreOK {
				t.Fatalf("APPLY-RLIMIT-CORE missing/unavailable: %+v", r.Findings)
			}
			if err := confine.RequireRlimitCoreZero(); err != nil {
				t.Fatal(err)
			}
			return
		}
		t.Fatal(err)
	}
	var saw bool
	for _, f := range r.Findings {
		if f.ID == "APPLY-RLIMIT-CORE" {
			saw = true
			if f.Status != confine.StatusAvailable {
				t.Fatalf("APPLY-RLIMIT-CORE: %+v", f)
			}
		}
	}
	if !saw {
		t.Fatal("missing APPLY-RLIMIT-CORE")
	}
	if err := confine.RequireRlimitCoreZero(); err != nil {
		t.Fatal(err)
	}
}

func TestRlimitCoreZeroSetrlimitOnly(t *testing.T) {
	// Coverage-safe on Linux: set RLIMIT_CORE only (no Landlock/seccomp).
	if !launcher.InTestSubprocess(t) {
		return
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireRlimitCoreZero(); err != nil {
		t.Fatal(err)
	}
}

func TestRequireRlimitCoreZeroBeforeApply(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	// Fresh processes typically have non-zero CORE soft/hard; Require must refuse.
	if err := confine.RequireRlimitCoreZero(); err == nil {
		t.Fatal("expected RequireRlimitCoreZero refusal before apply")
	}
}
