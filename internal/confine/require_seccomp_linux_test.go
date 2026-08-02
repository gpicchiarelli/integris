//go:build linux

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestRequireSeccompFilterAfterApply(t *testing.T) {
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
		if f.ID == "APPLY-SECCOMP" {
			saw = true
			if f.Status != confine.StatusAvailable {
				t.Fatalf("APPLY-SECCOMP: %+v", f)
			}
		}
	}
	if !saw {
		t.Fatal("missing APPLY-SECCOMP")
	}
	if err := confine.RequireSeccompFilter(); err != nil {
		t.Fatal(err)
	}
}

func TestRequireSeccompFilterBeforeApply(t *testing.T) {
	// Coverage-safe: no Landlock; fresh process must not be in FILTER mode.
	if !launcher.InTestSubprocess(t) {
		return
	}
	if err := confine.RequireSeccompFilter(); err == nil {
		t.Fatal("expected RequireSeccompFilter refusal before apply")
	}
}
