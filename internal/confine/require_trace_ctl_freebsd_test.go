//go:build freebsd

package confine_test

import (
	"os"
	"testing"
	"unsafe"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
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

func TestTraceCtlDisableWithoutCapEnter(t *testing.T) {
	// Coverage-safe: DISABLE only (no CapEnter namespace lock).
	if !launcher.InTestSubprocess(t) {
		return
	}
	mode := int32(2)              // PROC_TRACE_CTL_DISABLE
	_, _, errno := unix.Syscall6( // nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
		unix.SYS_PROCCTL,
		0, // P_PID
		uintptr(os.Getpid()),
		7, // PROC_TRACE_CTL
		uintptr(unsafe.Pointer(&mode)),
		0,
		0,
	)
	if errno != 0 {
		t.Fatal(errno)
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
