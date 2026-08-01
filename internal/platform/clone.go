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
// clone path). Applies SyncFile before close. Copies extended attributes, BSD
// flags, ACL (when supported), and atime/mtime last (clonefile preserves these;
// byte-copy would otherwise drop them).
func copyFileExclusive(dst, src string) error {
	if dst == "" || src == "" {
		return fmt.Errorf("platform: empty clone path")
	}
	// Capture times before opening src (read may bump atime).
	saved, err := readSourceTimes(src)
	if err != nil {
		return err
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
	// Xattr before ACL so Darwin ACL APIs own com.apple.system.Security.
	// Times last so prior metadata ops do not clobber atime/mtime.
	if err := copyXattr(dst, src); err != nil {
		return err
	}
	if err := copyBSDFlags(dst, src); err != nil {
		return err
	}
	if ACLSupported() {
		if err := copyACL(dst, src); err != nil {
			return err
		}
	}
	if err := syncAndApplyTimes(dst, saved); err != nil {
		return err
	}
	cleanup = false
	return nil
}
