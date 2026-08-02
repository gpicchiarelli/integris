//go:build !linux

package confine

import "runtime"

// NegativeDumpable is Linux-only (PR_GET_DUMPABLE); skipped elsewhere.
func NegativeDumpable() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-DUMPABLE", Platform: plat, Control: "dumpable",
		Status: StatusSkipped, Detail: "dumpable clear probe is Linux-only",
	}
}
