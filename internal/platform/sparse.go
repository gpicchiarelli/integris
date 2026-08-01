package platform

import (
	"io"
	"os"
)

// copyFileContents copies src→dst preserving sparse holes when SEEK_DATA /
// SEEK_HOLE are available. On Linux, falls back to copy_file_range(2) before
// io.Copy when sparse seeking fails.
func copyFileContents(dst, src *os.File) error {
	if err := copySparseContents(dst, src); err == nil {
		return nil
	}
	if err := rewindPair(dst, src); err != nil {
		return err
	}
	if err := copyFileRangeAll(dst, src); err == nil {
		return nil
	}
	if err := rewindPair(dst, src); err != nil {
		return err
	}
	_, err := io.Copy(dst, src)
	return err
}

func rewindPair(dst, src *os.File) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := dst.Truncate(0); err != nil {
		return err
	}
	_, err := dst.Seek(0, io.SeekStart)
	return err
}
