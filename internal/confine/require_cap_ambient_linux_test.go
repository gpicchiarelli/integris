//go:build linux

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
)

func TestRequireCapAmbientEmptyAfterApply(t *testing.T) {
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

func TestCapAmbientClearWithoutLandlock(t *testing.T) {
	// Coverage-safe: clear ambient only (no Landlock/seccomp).
	if !launcher.InTestSubprocess(t) {
		return
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireCapAmbientEmpty(); err != nil {
		t.Fatal(err)
	}
}
