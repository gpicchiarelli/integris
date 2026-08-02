//go:build !unix

package localsync

import "os"

func resolveRootsAt(source, destination string, srcFD, dstFD *os.File) (Roots, error) {
	_ = srcFD
	_ = dstFD
	return ResolveRoots(source, destination, true)
}

func ensureMetaReadyAt(destFD *os.File) error {
	_ = destFD
	return nil
}
