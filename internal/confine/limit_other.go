//go:build !freebsd

package confine

import "os"

// LimitConferredFDs is a no-op off FreeBSD.
func LimitConferredFDs(files ...*os.File) Finding {
	return Finding{
		ID: "APPLY-CAP-RIGHTS", Platform: "n/a", Control: "cap_rights_limit",
		Status: StatusSkipped, Detail: "cap_rights_limit is FreeBSD-only",
	}
}
