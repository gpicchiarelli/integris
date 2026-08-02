//go:build unix

package journal

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenFileSegmentAt opens name (single path component) under dirfd for
// read/write append, creating it if needed (M3f CapEnter-safe reopen).
func OpenFileSegmentAt(dirfd int, name string) (*FileSegment, error) {
	if name == "" || name == "." || name == ".." ||
		strings.Contains(name, "/") || strings.Contains(name, `\`) ||
		strings.Contains(name, string(rune(0))) {
		return nil, fmt.Errorf("journal: invalid segment name %q", name)
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &FileSegment{f: f, size: st.Size()}, nil
}
