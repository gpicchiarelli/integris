//go:build linux

package confine

import "runtime"

// NegativeSeccompFilter reports whether SECCOMP_MODE_FILTER is active after
// ApplyEngineering (M5w). Uses PR_GET_SECCOMP.
func NegativeSeccompFilter() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	filter, err := seccompModeFilter()
	if err != nil {
		return Finding{
			ID: "NEG-SECCOMP", Platform: plat, Control: "seccomp_bpf",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	if !filter {
		return Finding{
			ID: "NEG-SECCOMP", Platform: plat, Control: "seccomp_bpf",
			Status: StatusUnexpectedAllow, Detail: "SECCOMP_MODE_FILTER unset after apply",
		}
	}
	return Finding{
		ID: "NEG-SECCOMP", Platform: plat, Control: "seccomp_bpf",
		Status: StatusAvailable, Detail: "PR_GET_SECCOMP SECCOMP_MODE_FILTER",
	}
}
