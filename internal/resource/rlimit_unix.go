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

func withSoftCPU(soft uint64, fn func() error) error {
	return withSoftRlimit(unix.RLIMIT_CPU, soft, "CPU", fn)
}

func withSoftNPROC(soft uint64, fn func() error) error {
	return withSoftRlimit(unix.RLIMIT_NPROC, soft, "NPROC", fn)
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
	setSoftRlimit(&next, soft)
	if err := unix.Setrlimit(res, &next); err != nil {
		return fmt.Errorf("resource: setrlimit %s: %w", name, err)
	}
	defer restoreRlimit(res, old)
	return fn()
}

// restoreRlimit puts back a saved Rlimit. On Darwin, lowering some soft limits
// (notably RLIMIT_NPROC) permanently clamps rlim_max to the previous soft
// value; retry with Max clamped so Cur can still be restored.
func restoreRlimit(res int, old unix.Rlimit) {
	if err := unix.Setrlimit(res, &old); err == nil {
		return
	}
	var now unix.Rlimit
	if err := unix.Getrlimit(res, &now); err != nil {
		return
	}
	retry := old
	if now.Max < retry.Max {
		retry.Max = now.Max
	}
	if retry.Cur > retry.Max {
		retry.Cur = retry.Max
	}
	_ = unix.Setrlimit(res, &retry)
}
