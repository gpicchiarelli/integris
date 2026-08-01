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
// clone path). Applies SyncFile before close. When ACLSupported, also copies
// the extended ACL (clonefile preserves ACLs; byte-copy would otherwise drop them).
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
		if out != nil {
			_ = out.Close()
		}
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
	if err := out.Close(); err != nil {
		return err
	}
	out = nil
	if ACLSupported() {
		if err := copyACL(dst, src); err != nil {
			return err
		}
		meta, err := os.Open(dst)
		if err != nil {
			return err
		}
		syncErr := SyncFile(meta)
		_ = meta.Close()
		if syncErr != nil {
			return syncErr
		}
	}
	cleanup = false
	return nil
}
