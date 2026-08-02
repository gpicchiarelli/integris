//go:build !freebsd

package confine

import "runtime"

// NegativeCapMode is FreeBSD-only (cap_getmode); skipped elsewhere.
func NegativeCapMode() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-CAP-MODE", Platform: plat, Control: "cap_getmode",
		Status: StatusSkipped, Detail: "cap_getmode not available on this OS",
	}
}
