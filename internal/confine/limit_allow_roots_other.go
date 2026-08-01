//go:build !freebsd

package confine

import "os"

// LimitAllowRootFDs is a no-op off FreeBSD (path allow-lists use Landlock,
// unveil, or Seatbelt instead of conferred directory fds).
func LimitAllowRootFDs(mode ArchiveFSMode, files ...*os.File) Finding {
	_ = mode
	_ = files
	return Finding{
		ID: "APPLY-CAP-ALLOW-ROOTS", Platform: "n/a", Control: "cap_rights_limit",
		Status: StatusSkipped, Detail: "allow-root directory fds are FreeBSD-only",
	}
}
