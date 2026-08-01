package platform

// CopyResourceFork copies a Darwin resource fork from src onto dst via
// path/..namedfork/rsrc. If src has no resource fork, CopyResourceFork is a
// successful no-op. On non-Darwin builds it is always a no-op.
func CopyResourceFork(dst, src string) error { return copyResourceFork(dst, src) }
