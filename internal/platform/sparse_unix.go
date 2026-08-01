//go:build unix

package platform

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

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
	const maxChunk = 1 << 20 // 1 MiB bounded copy buffer
	buf := make([]byte, maxChunk)
	var offset int64
	for offset < size {
		dataOff, err := src.Seek(offset, unix.SEEK_DATA)
		if err != nil {
			if errors.Is(err, unix.ENXIO) {
				// No more data extents; trailing hole already covered by Truncate.
				return nil
			}
			return err
		}
		if dataOff >= size {
			return nil
		}
		holeOff, err := src.Seek(dataOff, unix.SEEK_HOLE)
		if err != nil {
			return err
		}
		if holeOff > size {
			holeOff = size
		}
		if holeOff <= dataOff {
			return fmt.Errorf("platform: sparse seek made no progress")
		}
		remaining := holeOff - dataOff
		pos := dataOff
		for remaining > 0 {
			n := remaining
			if n > maxChunk {
				n = maxChunk
			}
			nr, err := src.ReadAt(buf[:n], pos)
			if nr > 0 {
				if _, werr := dst.WriteAt(buf[:nr], pos); werr != nil {
					return werr
				}
				pos += int64(nr)
				remaining -= int64(nr)
			}
			if err != nil {
				if errors.Is(err, io.EOF) && remaining == 0 {
					break
				}
				if errors.Is(err, io.EOF) {
					return io.ErrUnexpectedEOF
				}
				return err
			}
		}
		offset = holeOff
	}
	return nil
}
