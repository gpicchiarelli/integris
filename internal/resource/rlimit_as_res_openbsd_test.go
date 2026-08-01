//go:build openbsd

package resource_test

import "golang.org/x/sys/unix"

func asLimitResource() int { return unix.RLIMIT_DATA }
