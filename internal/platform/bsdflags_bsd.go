//go:build darwin || freebsd || openbsd

package platform

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func copyBSDFlags(dst, src string) error {
	if dst == "" || src == "" {
		return fmt.Errorf("platform: empty bsdflags path")
	}
	var st unix.Stat_t
	if err := unix.Stat(src, &st); err != nil {
		return fmt.Errorf("platform: stat for flags: %w", err)
	}
	if err := unix.Chflags(dst, int(st.Flags)); err != nil {
		return fmt.Errorf("platform: chflags: %w", err)
	}
	return nil
}
