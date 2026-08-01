//go:build linux

package platform

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// PreferredCloneMechanism is the native clone primitive for this build.
func PreferredCloneMechanism() string { return CloneMechanismFiclone }

// CloneFile materializes dst as a clone of src. Prefers Linux FICLONE
// (Btrfs/XFS reflink); on unsupported/cross-device errors falls back to
// exclusive byte copy (explicit degraded mode).
func CloneFile(dst, src string) (mechanism string, err error) {
	if dst == "" || src == "" {
		return "", fmt.Errorf("platform: empty clone path")
	}
	if err := tryFiclone(dst, src); err == nil {
		return CloneMechanismFiclone, nil
	} else if !cloneFallback(err) {
		return "", err
	}
	if err := copyFileExclusive(dst, src); err != nil {
		return "", err
	}
	return CloneMechanismCopy, nil
}

func tryFiclone(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
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
	if err := unix.IoctlFileClone(int(out.Fd()), int(in.Fd())); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func cloneFallback(err error) bool {
	return errors.Is(err, unix.EXDEV) ||
		errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOSYS) ||
		os.IsPermission(err)
}
