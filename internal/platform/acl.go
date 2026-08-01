package platform

// ACLSupported reports whether ACLRoundTrip can exercise native ACL APIs
// on this build (Darwin with cgo).
func ACLSupported() bool { return aclSupported }

// ACLRoundTrip sets and reads back an extended ACL on path.
// Path must already exist as a regular file. Returns nil on success.
func ACLRoundTrip(path string) error { return aclRoundTrip(path) }
