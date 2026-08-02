//go:build linux

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
)

func TestRequireCapAmbientEmptyAfterApply(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	r := confine.ApplyEngineering(authority.RoleApply)
	if err := r.RequireApplyAvailable(); err != nil {
		t.Fatal(err)
	}
	var sawAmbient bool
	for _, f := range r.Findings {
		if f.ID == "APPLY-CAP-AMBIENT" {
			sawAmbient = true
			if f.Status != confine.StatusAvailable {
				t.Fatalf("APPLY-CAP-AMBIENT: %+v", f)
			}
		}
	}
	if !sawAmbient {
		t.Fatal("missing APPLY-CAP-AMBIENT")
	}
	if err := confine.RequireCapAmbientEmpty(); err != nil {
		t.Fatal(err)
	}
}
