//go:build openbsd

package resource

import "golang.org/x/sys/unix"

// OpenBSD has no RLIMIT_AS; RLIMIT_DATA covers anonymous mmap (except MAP_STACK).
func withSoftAS(soft uint64, fn func() error) error {
	return withSoftRlimit(unix.RLIMIT_DATA, soft, "AS", fn)
}
