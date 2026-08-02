//go:build unix

package launcher

import (
	"os"
	"strconv"
	"strings"
)

// ClaimAllowRootFDs adopts conferred directory FDs listed in
// INTEGRIS_ALLOW_ROOT_FDS (comma-separated fd numbers from ExtraFiles).
func ClaimAllowRootFDs(raw string) []*os.File {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]*os.File, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		fd, err := strconv.Atoi(p)
		if err != nil || fd < 0 {
			continue
		}
		f := os.NewFile(uintptr(fd), "allow-root-"+p)
		if f != nil {
			out = append(out, f)
		}
	}
	return out
}

// CloseAllowRootFDs closes conferred allow-root directory descriptors.
func CloseAllowRootFDs(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
