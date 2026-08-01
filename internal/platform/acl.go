package platform

// ACLSupported reports whether ACLRoundTrip / CopyACL can exercise native ACL
// APIs on this build (Darwin with cgo).
func ACLSupported() bool { return aclSupported }

// ACLRoundTrip sets and reads back an extended ACL on path.
// Path must already exist as a regular file. Returns nil on success.
func ACLRoundTrip(path string) error { return aclRoundTrip(path) }

// CopyACL copies the extended ACL from src onto dst. If src has no extended
// ACL, CopyACL is a successful no-op. Both paths must exist as regular files.
func CopyACL(dst, src string) error { return copyACL(dst, src) }
