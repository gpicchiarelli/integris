//go:build !unix

package localsync

import "os"

// Non-Unix builds use plain open; symlink refusal still happens at Lstat scan.
func openFileNOFOLLOW(nativePath string) (*os.File, error) {
	return os.Open(nativePath)
}
