//go:build unix

package resource

import (
	"fmt"
	"os/signal"

	"golang.org/x/sys/unix"
)

func withSoftNOFILE(soft uint64, fn func() error) error {
	return withSoftRlimit(unix.RLIMIT_NOFILE, soft, "NOFILE", fn)
}

func withSoftFSIZE(soft uint64, fn func() error) error {
	if fn == nil {
		return fmt.Errorf("resource: nil WithSoftFSIZE func")
	}
	signal.Ignore(unix.SIGXFSZ)
	defer signal.Reset(unix.SIGXFSZ)
	return withSoftRlimit(unix.RLIMIT_FSIZE, soft, "FSIZE", fn)
}

func withSoftRlimit(res int, soft uint64, name string, fn func() error) error {
	if fn == nil {
		return fmt.Errorf("resource: nil WithSoft%s func", name)
	}
	var old unix.Rlimit
	if err := unix.Getrlimit(res, &old); err != nil {
		return fmt.Errorf("resource: getrlimit %s: %w", name, err)
	}
	if soft == 0 {
		return fmt.Errorf("resource: soft %s must be > 0", name)
	}
	next := old
	if soft > old.Max {
		soft = old.Max
	}
	next.Cur = soft
	if err := unix.Setrlimit(res, &next); err != nil {
		return fmt.Errorf("resource: setrlimit %s: %w", name, err)
	}
	defer func() {
		_ = unix.Setrlimit(res, &old)
	}()
	return fn()
}
