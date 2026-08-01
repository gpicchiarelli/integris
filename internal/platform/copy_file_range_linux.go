//go:build linux

package platform

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// copyFileRangeAll copies src→dst via copy_file_range(2), looping until EOF.
// Returns an error when the syscall is unavailable or fails so callers can
// fall back to io.Copy.
func copyFileRangeAll(dst, src *os.File) error {
	st, err := src.Stat()
	if err != nil {
		return err
	}
	remaining := st.Size()
	if remaining < 0 {
		return io.ErrUnexpectedEOF
	}
	if remaining == 0 {
		return nil
	}
	for remaining > 0 {
		chunk := remaining
		if chunk > 1<<30 {
			chunk = 1 << 30
		}
		n, err := unix.CopyFileRange(int(src.Fd()), nil, int(dst.Fd()), nil, int(chunk), 0)
		if n == 0 && err == nil {
			return io.ErrUnexpectedEOF
		}
		if err != nil {
			return err
		}
		remaining -= int64(n)
	}
	return nil
}
