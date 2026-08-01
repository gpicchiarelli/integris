//go:build linux

package main

import "golang.org/x/sys/unix"

func applyBestEffortConfinement() {
	// Engineering preview: refuse privilege gains after start. Not Landlock/seccomp.
	_ = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}
