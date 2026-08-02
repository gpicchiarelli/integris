//go:build unix

package localsync

import (
	"os"

	"golang.org/x/sys/unix"
)

func openFileNOFOLLOW(nativePath string) (*os.File, error) {
	fd, err := unix.Open(nativePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), nativePath), nil
}
