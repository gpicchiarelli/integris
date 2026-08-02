//go:build !unix

package confine

import "runtime"

// NegativeRlimitCore is Unix-only (getrlimit RLIMIT_CORE); skipped elsewhere.
func NegativeRlimitCore() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
		Status: StatusSkipped, Detail: "RLIMIT_CORE zero probe is Unix-only",
	}
}
