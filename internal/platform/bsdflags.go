package platform

// CopyBSDFlags copies BSD file flags from src onto dst via chflags(2).
// On platforms without BSD flags, CopyBSDFlags is a successful no-op.
func CopyBSDFlags(dst, src string) error { return copyBSDFlags(dst, src) }
