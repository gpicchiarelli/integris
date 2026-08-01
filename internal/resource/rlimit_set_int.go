//go:build freebsd || openbsd || netbsd || dragonfly

package resource

import "golang.org/x/sys/unix"

func setSoftRlimit(next *unix.Rlimit, soft uint64) {
	// BSD Rlimit fields are int64; RLIM_INFINITY is typically -1.
	if next.Max >= 0 && soft > uint64(next.Max) {
		soft = uint64(next.Max)
	}
	next.Cur = int64(soft)
}
