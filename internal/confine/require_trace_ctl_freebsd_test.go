//go:build freebsd

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestRequireTraceCtlDisabledAfterApply(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	r := confine.ApplyEngineering(authority.RoleApply)
	if err := r.RequireApplyAvailable(); err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, f := range r.Findings {
		if f.ID == "APPLY-TRACE-CTL" {
			saw = true
			if f.Status != confine.StatusAvailable {
				t.Fatalf("APPLY-TRACE-CTL: %+v", f)
			}
		}
	}
	if !saw {
		t.Fatal("missing APPLY-TRACE-CTL")
	}
	if err := confine.RequireTraceCtlDisabled(); err != nil {
		t.Fatal(err)
	}
}

func TestRequireTraceCtlDisabledBeforeApply(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	if err := confine.RequireTraceCtlDisabled(); err == nil {
		t.Fatal("expected RequireTraceCtlDisabled refusal before apply")
	}
}
