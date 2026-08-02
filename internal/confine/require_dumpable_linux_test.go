//go:build linux

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
)

func TestRequireDumpableClearAfterApply(t *testing.T) {
	if testing.CoverMode() != "" {
		// Landlock in this process blocks go cover meta writes under /tmp.
		t.Skip("Landlock apply blocks coverage meta under -cover")
	}
	if !launcher.InTestSubprocess(t) {
		return
	}
	r := confine.ApplyEngineering(authority.RoleApply)
	if err := r.RequireApplyAvailable(); err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, f := range r.Findings {
		if f.ID == "APPLY-DUMPABLE" {
			saw = true
			if f.Status != confine.StatusAvailable {
				t.Fatalf("APPLY-DUMPABLE: %+v", f)
			}
		}
	}
	if !saw {
		t.Fatal("missing APPLY-DUMPABLE")
	}
	if err := confine.RequireDumpableClear(); err != nil {
		t.Fatal(err)
	}
}

func TestDumpableClearWithoutLandlock(t *testing.T) {
	// Coverage-safe: clear dumpable only (no Landlock/seccomp).
	if !launcher.InTestSubprocess(t) {
		return
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireDumpableClear(); err != nil {
		t.Fatal(err)
	}
}

func TestRequireDumpableClearBeforeApply(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	if err := confine.RequireDumpableClear(); err == nil {
		t.Fatal("expected RequireDumpableClear refusal before apply")
	}
}
