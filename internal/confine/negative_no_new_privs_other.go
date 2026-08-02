//go:build !linux

package confine

import "runtime"

// NegativeNoNewPrivs is Linux-only (PR_GET_NO_NEW_PRIVS); skipped elsewhere.
func NegativeNoNewPrivs() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs",
		Status: StatusSkipped, Detail: "PR_NO_NEW_PRIVS is Linux-only",
	}
}
