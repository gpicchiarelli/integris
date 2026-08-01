package platform

import (
	"fmt"
	"os"
)

// SyncDir opens path and applies SyncFile to the directory descriptor.
func SyncDir(path string) error {
	if path == "" {
		return fmt.Errorf("platform: empty sync path")
	}
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return SyncFile(d)
}
