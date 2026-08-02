//go:build unix

package remotesync

import (
	"os"

	"golang.org/x/sys/unix"
)

func dupDirFile(dirfd int, name string) (*os.File, error) {
	dup, err := unix.Dup(dirfd)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(dup), name), nil
}
