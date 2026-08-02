//go:build !linux

package confine

import "runtime"

// NegativeSeccompFilter is Linux-only (PR_GET_SECCOMP); skipped elsewhere.
func NegativeSeccompFilter() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-SECCOMP", Platform: plat, Control: "seccomp_bpf",
		Status: StatusSkipped, Detail: "seccomp filter mode probe is Linux-only",
	}
}
