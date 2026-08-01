//go:build unix

package confine

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// NegativeExec attempts execve of a well-known path via unix.Exec (not os/exec).
// Under Linux seccomp / OpenBSD pledge / FreeBSD capability mode this should
// fail and return. Darwin skips (ApplyEngineering is a no-op).
func NegativeExec() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	switch runtime.GOOS {
	case "linux", "openbsd", "freebsd":
	default:
		return Finding{
			ID: "NEG-EXEC", Platform: plat, Control: "process_exec",
			Status: StatusSkipped, Detail: "no engineering exec denylist on this OS",
		}
	}
	err := unix.Exec("/bin/true", []string{"/bin/true"}, nil)
	// Success replaces the process image and does not return.
	if err == nil {
		return Finding{
			ID: "NEG-EXEC", Platform: plat, Control: "process_exec",
			Status: StatusUnexpectedAllow, Detail: "exec returned nil (unreachable)",
		}
	}
	return Finding{
		ID: "NEG-EXEC", Platform: plat, Control: "process_exec",
		Status: StatusDeniedExpected, Detail: err.Error(),
	}
}

// NegativePtrace attempts a ptrace request that Linux seccomp should deny.
// Non-Linux platforms skip (denylist is seccomp-oriented).
func NegativePtrace() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	if runtime.GOOS != "linux" {
		return Finding{
			ID: "NEG-PTRACE", Platform: plat, Control: "ptrace",
			Status: StatusSkipped, Detail: "ptrace denylist probe is Linux seccomp-oriented",
		}
	}
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
