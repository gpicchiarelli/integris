package platform

import (
	"fmt"
	"io"
	"os"
)

// Clone mechanisms reported by CloneFile.
const (
	CloneMechanismClonefile = "clonefile"
	CloneMechanismCopy      = "copy"
)

// copyFileExclusive creates dst exclusively and copies src bytes (degraded
// clone path). Applies SyncFile before close.
func copyFileExclusive(dst, src string) error {
	if dst == "" || src == "" {
		return fmt.Errorf("platform: empty clone path")
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = out.Close()
		if cleanup {
			_ = os.Remove(dst)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := SyncFile(out); err != nil {
		return err
	}
	cleanup = false
	return nil
}
