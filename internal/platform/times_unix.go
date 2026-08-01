//go:build unix

package platform

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type sourceTimes struct {
	atime    unix.Timespec
	mtime    unix.Timespec
	birth    unix.Timespec
	hasBirth bool
}

func readSourceTimes(path string) (sourceTimes, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return sourceTimes{}, fmt.Errorf("platform: stat for times: %w", err)
	}
	saved := sourceTimes{atime: st.Atim, mtime: st.Mtim}
	captureBirth(&st, &saved)
	return saved, nil
}

func copyTimes(dst, src string) error {
	if dst == "" || src == "" {
		return fmt.Errorf("platform: empty times path")
	}
	saved, err := readSourceTimes(src)
	if err != nil {
		return err
	}
	at := time.Unix(saved.atime.Sec, saved.atime.Nsec)
	mt := time.Unix(saved.mtime.Sec, saved.mtime.Nsec)
	if err := os.Chtimes(dst, at, mt); err != nil {
		return fmt.Errorf("platform: chtimes: %w", err)
	}
	if err := applyBirth(dst, saved); err != nil {
		return err
	}
	return nil
}

// syncAndApplyTimes SyncFile's dst then restores the pre-captured times.
// Times are set after the durability barrier so open/fsync cannot bump them.
func syncAndApplyTimes(dst string, saved sourceTimes) error {
	if dst == "" {
		return fmt.Errorf("platform: empty times path")
	}
	meta, err := os.OpenFile(dst, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	syncErr := SyncFile(meta)
	_ = meta.Close()
	if syncErr != nil {
		return syncErr
	}
	ts := []unix.Timespec{saved.atime, saved.mtime}
	if err := unix.UtimesNano(dst, ts); err != nil {
		return fmt.Errorf("platform: utimens: %w", err)
	}
	if err := applyBirth(dst, saved); err != nil {
		return err
	}
	return nil
}
