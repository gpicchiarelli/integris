//go:build !linux

package confine

import "runtime"

// NegativeCapAmbient is Linux-only (PR_CAP_AMBIENT / CapAmb); skipped elsewhere.
func NegativeCapAmbient() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-CAP-AMBIENT", Platform: plat, Control: "empty_capability_set",
		Status: StatusSkipped, Detail: "ambient capability clear is Linux-only",
	}
}
