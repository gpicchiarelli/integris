//go:build linux

package confine

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// NegativePtrace attempts a ptrace request that Linux seccomp should deny.
func NegativePtrace() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	err := unix.PtraceAttach(unix.Getpid())
	if err == nil {
		_ = unix.PtraceDetach(unix.Getpid())
		return Finding{
			ID: "NEG-PTRACE", Platform: plat, Control: "ptrace",
			Status: StatusUnexpectedAllow, Detail: "ptrace attach to self succeeded",
		}
	}
	return Finding{
		ID: "NEG-PTRACE", Platform: plat, Control: "ptrace",
		Status: StatusDeniedExpected, Detail: err.Error(),
	}
}
