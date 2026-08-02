//go:build linux

package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
)

func TestRequireNoNewPrivsSetAfterApply(t *testing.T) {
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
		if f.ID == "APPLY-NO-NEW-PRIVS" {
			saw = true
			if f.Status != confine.StatusAvailable {
				t.Fatalf("APPLY-NO-NEW-PRIVS: %+v", f)
			}
		}
	}
	if !saw {
		t.Fatal("missing APPLY-NO-NEW-PRIVS")
	}
	if err := confine.RequireNoNewPrivsSet(); err != nil {
		t.Fatal(err)
	}
}

func TestNoNewPrivsSetWithoutLandlock(t *testing.T) {
	// Coverage-safe: set no_new_privs only (no Landlock/seccomp).
	if !launcher.InTestSubprocess(t) {
		return
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := confine.RequireNoNewPrivsSet(); err != nil {
		t.Fatal(err)
	}
}
