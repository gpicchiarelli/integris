//go:build darwin

package platform

import (
	"fmt"
	"os"
)

func namedForkPath(path string) string {
	return path + "/..namedfork/rsrc"
}

func copyResourceFork(dst, src string) error {
	if dst == "" || src == "" {
		return fmt.Errorf("platform: empty rfork path")
	}
	data, err := os.ReadFile(namedForkPath(src))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("platform: read resource fork: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	dstRF := namedForkPath(dst)
	if err := os.WriteFile(dstRF, data, 0o600); err != nil {
		return fmt.Errorf("platform: write resource fork: %w", err)
	}
	f, err := os.OpenFile(dstRF, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	syncErr := SyncFile(f)
	_ = f.Close()
	return syncErr
}
