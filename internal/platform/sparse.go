package platform

import (
	"io"
	"os"
)

// copyFileContents copies src→dst preserving sparse holes when SEEK_DATA /
// SEEK_HOLE are available. Falls back to io.Copy when sparse seeking fails.
func copyFileContents(dst, src *os.File) error {
	if err := copySparseContents(dst, src); err == nil {
		return nil
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := dst.Truncate(0); err != nil {
		return err
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := io.Copy(dst, src)
	return err
}
