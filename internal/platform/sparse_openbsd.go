//go:build openbsd

package platform

import (
	"fmt"
	"io"
	"os"
)

// OpenBSD x/sys lacks SEEK_DATA/SEEK_HOLE. Fall back to a dense bounded copy;
// CapSparse probes already report unrepresentable where hole APIs are absent.
func copySparseContents(dst, src *os.File) error {
	st, err := src.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	if err := dst.Truncate(size); err != nil {
		return fmt.Errorf("platform: truncate for sparse copy: %w", err)
	}
	if size == 0 {
		return nil
	}
	const maxChunk = 1 << 20
	buf := make([]byte, maxChunk)
	var offset int64
	for offset < size {
		n := size - offset
		if n > maxChunk {
			n = maxChunk
		}
		nr, rerr := src.ReadAt(buf[:n], offset)
		if nr > 0 {
			if _, werr := dst.WriteAt(buf[:nr], offset); werr != nil {
				return werr
			}
			offset += int64(nr)
		}
		if rerr != nil {
			if rerr == io.EOF && offset >= size {
				return nil
			}
			if rerr == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return rerr
		}
	}
	return nil
}
