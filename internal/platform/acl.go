package platform

// ACLSupported reports whether ACLRoundTrip / CopyACL can exercise native ACL
// APIs on this build (Darwin with cgo, or Linux POSIX ACL xattrs).
func ACLSupported() bool { return aclSupported }

// ACLRoundTrip sets and reads back an extended/POSIX ACL on path.
// Path must already exist as a regular file. Returns nil on success.
func ACLRoundTrip(path string) error { return aclRoundTrip(path) }

// CopyACL copies the extended/POSIX ACL from src onto dst. If src has no
// ACL, CopyACL is a successful no-op. Both paths must exist as regular files.
func CopyACL(dst, src string) error { return copyACL(dst, src) }
