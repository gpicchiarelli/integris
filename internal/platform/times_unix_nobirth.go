//go:build unix && !darwin

package platform

import "golang.org/x/sys/unix"

func captureBirth(st *unix.Stat_t, saved *sourceTimes) {
	_ = st
	_ = saved
}

func applyBirth(path string, saved sourceTimes) error {
	_, _ = path, saved
	return nil
}
