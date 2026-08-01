//go:build unix && !darwin

package platform

import "golang.org/x/sys/unix"

func captureBirth(st *unix.Stat_t, saved *sourceTimes) {
	_ = st
	saved.birth = unix.Timespec{}
	saved.hasBirth = false
}

func applyBirth(path string, saved sourceTimes) error {
	_ = path
	if saved.hasBirth {
		_ = saved.birth
	}
	return nil
}
