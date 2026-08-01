//go:build unix && !openbsd

package platform

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func sendFileSupported() bool { return true }

func sendFile(out, in *os.File, offset int64, count int) (int, int64, error) {
	off := offset
	n, err := unix.Sendfile(int(out.Fd()), int(in.Fd()), &off, count)
	runtime.KeepAlive(out)
	runtime.KeepAlive(in)
	if n < 0 {
		n = 0
	}
	if n == 0 && err != nil {
		return 0, offset, err
	}
	// Darwin's x/sys wrapper does not advance *offset; Linux/FreeBSD do.
	if off == offset {
		off = offset + int64(n)
	}
	return n, off, err
}
