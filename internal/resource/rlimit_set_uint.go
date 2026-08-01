//go:build unix && !freebsd && !openbsd && !netbsd && !dragonfly

package resource

import "golang.org/x/sys/unix"

func setSoftRlimit(next *unix.Rlimit, soft uint64) {
	if soft > next.Max {
		soft = next.Max
	}
	next.Cur = soft
}
