//go:build !unix

package confine

import "runtime"

// NegativeExec is unavailable off Unix.
func NegativeExec() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-EXEC", Platform: plat, Control: "process_exec",
		Status: StatusSkipped, Detail: "unix only",
	}
}

// NegativePtrace is unavailable off Unix.
func NegativePtrace() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-PTRACE", Platform: plat, Control: "ptrace",
		Status: StatusSkipped, Detail: "unix only",
	}
}
