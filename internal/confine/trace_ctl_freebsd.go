//go:build freebsd

package confine

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FreeBSD procctl(2) TRACE_CTL constants (sys/procctl.h). x/sys has SYS_PROCCTL
// but no typed wrappers — same raw-syscall precedent as launcher keyfd.
const (
	pPID                = 0 // P_PID
	procTraceCtl        = 7 // PROC_TRACE_CTL
	procTraceCtlDisable = 2 // PROC_TRACE_CTL_DISABLE
	procTraceStatus     = 8 // PROC_TRACE_STATUS
)

// applyTraceCtlFinding disables ptrace/ktrace/core via PROC_TRACE_CTL_DISABLE
// and verifies PROC_TRACE_STATUS == -1 (M6c). Process-wide; set before CapEnter.
// DISABLE (not DISABLE_EXEC): CapEnter already denies execve; we do not claim
// persistence across exec. Self can still PROC_TRACE_CTL_ENABLE (same class as
// re-PR_SET_DUMPABLE).
func applyTraceCtlFinding(plat string) Finding {
	if err := procTraceCtlSetDisable(); err != nil {
		return Finding{
			ID: "APPLY-TRACE-CTL", Platform: plat, Control: "proc_trace_ctl",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	disabled, err := procTraceDisabled()
	if err != nil {
		return Finding{
			ID: "APPLY-TRACE-CTL", Platform: plat, Control: "proc_trace_ctl",
			Status: StatusUnavailable, Detail: "verify: " + err.Error(),
		}
	}
	if !disabled {
		return Finding{
			ID: "APPLY-TRACE-CTL", Platform: plat, Control: "proc_trace_ctl",
			Status: StatusUnavailable, Detail: "PROC_TRACE_STATUS not -1 after DISABLE",
		}
	}
	return Finding{
		ID: "APPLY-TRACE-CTL", Platform: plat, Control: "proc_trace_ctl",
		Status: StatusAvailable, Detail: "PROC_TRACE_CTL_DISABLE; STATUS=-1 verified",
	}
}

// NegativeTraceCtl reports whether PROC_TRACE_STATUS is -1 after
// ApplyEngineering (M6c).
func NegativeTraceCtl() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	disabled, err := procTraceDisabled()
	if err != nil {
		return Finding{
			ID: "NEG-TRACE-CTL", Platform: plat, Control: "proc_trace_ctl",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	if !disabled {
		return Finding{
			ID: "NEG-TRACE-CTL", Platform: plat, Control: "proc_trace_ctl",
			Status: StatusUnexpectedAllow, Detail: "PROC_TRACE_STATUS not disabled after apply",
		}
	}
	return Finding{
		ID: "NEG-TRACE-CTL", Platform: plat, Control: "proc_trace_ctl",
		Status: StatusAvailable, Detail: "PROC_TRACE_STATUS=-1",
	}
}

func procTraceCtlSetDisable() error {
	mode := int32(procTraceCtlDisable)
	return procctl(procTraceCtl, unsafe.Pointer(&mode))
}

func procTraceDisabled() (bool, error) {
	var status int32
	if err := procctl(procTraceStatus, unsafe.Pointer(&status)); err != nil {
		return false, err
	}
	return status == -1, nil
}

func procctl(com int, data unsafe.Pointer) error {
	pid := os.Getpid()
	_, _, errno := unix.Syscall6( // nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
		unix.SYS_PROCCTL,
		uintptr(pPID),
		uintptr(pid),
		uintptr(com),
		uintptr(data),
		0,
		0,
	)
	if errno != 0 {
		// Older kernels reject non-zero id quirks; try id=0 (current process).
		if pid != 0 {
			_, _, errno0 := unix.Syscall6(
				unix.SYS_PROCCTL,
				uintptr(pPID),
				0,
				uintptr(com),
				uintptr(data),
				0,
				0,
			)
			if errno0 == 0 {
				return nil
			}
		}
		return errno
	}
	return nil
}
