//go:build freebsd

package launcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// openAllowRootDirs opens absolute directory roots for ExtraFiles conferral.
// Caller must Close the returned files after Start (child holds dup'd fds).
func openAllowRootDirs(roots []string) (files []*os.File, childFDs []int, err error) {
	if len(roots) == 0 {
		return nil, nil, nil
	}
	files = make([]*os.File, 0, len(roots))
	for _, root := range roots {
		if root == "" || !filepath.IsAbs(root) {
			closeFiles(files)
			return nil, nil, fail("allow_roots", "root must be absolute: "+root)
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			closeFiles(files)
			return nil, nil, fail("allow_roots", err.Error())
		}
		fd, err := unix.Open(resolved, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			closeFiles(files)
			return nil, nil, fail("allow_roots", fmt.Sprintf("open %s: %v", resolved, err))
		}
		files = append(files, os.NewFile(uintptr(fd), resolved))
	}
	return files, nil, nil
}

func allowRootFDEnv(extraStartIndex int, n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = strconv.Itoa(3 + extraStartIndex + i)
	}
	return strings.Join(parts, ",")
}

func closeFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
