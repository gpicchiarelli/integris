//go:build unix && !darwin && !openbsd

package resource

import "golang.org/x/sys/unix"

func withSoftAS(soft uint64, fn func() error) error {
	return withSoftRlimit(unix.RLIMIT_AS, soft, "AS", fn)
}
