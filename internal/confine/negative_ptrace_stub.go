//go:build !linux

package confine

import "runtime"

// NegativePtrace is a no-op stub off Linux; the denylist probe is seccomp-oriented.
func NegativePtrace() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-PTRACE", Platform: plat, Control: "ptrace",
		Status: StatusSkipped, Detail: "ptrace denylist probe is Linux seccomp-oriented",
	}
}
