//go:build !unix

package localsync

import "os"

// ScanAt is Unix-only (openat dirfd walk).
func ScanAt(rootFD *os.File, rootLabel string) (Manifest, error) {
	_ = rootFD
	_ = rootLabel
	return Manifest{}, unsupported("scanat", "", "dirfd scan requires unix")
}
