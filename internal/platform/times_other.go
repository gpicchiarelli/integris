//go:build !unix

package platform

import (
	"fmt"
	"os"
	"time"
)

type sourceTimes struct {
	mod time.Time
}

func readSourceTimes(path string) (sourceTimes, error) {
	info, err := os.Stat(path)
	if err != nil {
		return sourceTimes{}, fmt.Errorf("platform: stat for times: %w", err)
	}
	return sourceTimes{mod: info.ModTime()}, nil
}

func copyTimes(dst, src string) error {
	if dst == "" || src == "" {
		return fmt.Errorf("platform: empty times path")
	}
	saved, err := readSourceTimes(src)
	if err != nil {
		return err
	}
	if err := os.Chtimes(dst, saved.mod, saved.mod); err != nil {
		return fmt.Errorf("platform: chtimes: %w", err)
	}
	return nil
}

func syncAndApplyTimes(dst string, saved sourceTimes) error {
	meta, err := os.OpenFile(dst, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	syncErr := SyncFile(meta)
	_ = meta.Close()
	if syncErr != nil {
		return syncErr
	}
	if err := os.Chtimes(dst, saved.mod, saved.mod); err != nil {
		return fmt.Errorf("platform: chtimes: %w", err)
	}
	return nil
}
