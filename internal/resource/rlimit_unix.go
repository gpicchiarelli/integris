//go:build unix

package resource

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func withSoftNOFILE(soft uint64, fn func() error) error {
	if fn == nil {
		return fmt.Errorf("resource: nil WithSoftNOFILE func")
	}
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
		return fmt.Errorf("resource: getrlimit NOFILE: %w", err)
	}
	next := old
	if soft == 0 {
		return fmt.Errorf("resource: soft NOFILE must be > 0")
	}
	if soft > old.Max {
		soft = old.Max
	}
	next.Cur = soft
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &next); err != nil {
		return fmt.Errorf("resource: setrlimit NOFILE: %w", err)
	}
	defer func() {
		_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &old)
	}()
	return fn()
}
