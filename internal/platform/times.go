package platform

// CopyTimes copies atime and mtime from src onto dst. On Darwin it also
// restores birthtime (ATTR_CMN_CRTIME). Call after other metadata mutations
// so they do not clobber the restored times.
func CopyTimes(dst, src string) error { return copyTimes(dst, src) }
