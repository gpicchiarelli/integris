package platform

// CopyXattr copies extended attributes from src onto dst. If src has no
// extended attributes, CopyXattr is a successful no-op. Both paths must exist.
// Darwin ACL material (com.apple.system.Security) is skipped; use CopyACL.
func CopyXattr(dst, src string) error { return copyXattr(dst, src) }
