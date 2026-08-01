//go:build unix && !freebsd && !dragonfly

package resource

import "golang.org/x/sys/unix"

func withSoftNPROC(soft uint64, fn func() error) error {
	return withSoftRlimit(unix.RLIMIT_NPROC, soft, "NPROC", fn)
}
