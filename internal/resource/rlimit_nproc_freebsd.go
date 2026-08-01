//go:build freebsd || dragonfly

package resource

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func withSoftNPROC(soft uint64, fn func() error) error {
	// FreeBSD does not reliably refuse fork when only the soft NPROC ceiling
	// is lowered; clamp hard max for the harness window as well.
	if fn == nil {
		return fmt.Errorf("resource: nil WithSoftNPROC func")
	}
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NPROC, &old); err != nil {
		return fmt.Errorf("resource: getrlimit NPROC: %w", err)
	}
	if soft == 0 {
		return fmt.Errorf("resource: soft NPROC must be > 0")
	}
	next := old
	setSoftAndHardRlimit(&next, soft)
	if err := unix.Setrlimit(unix.RLIMIT_NPROC, &next); err != nil {
		return fmt.Errorf("resource: setrlimit NPROC: %w", err)
	}
	defer restoreRlimit(unix.RLIMIT_NPROC, old)
	return fn()
}
