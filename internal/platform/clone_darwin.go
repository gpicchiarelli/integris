//go:build darwin

package platform

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// PreferredCloneMechanism is the native clone primitive for this build.
func PreferredCloneMechanism() string { return CloneMechanismClonefile }

// CloneFile materializes dst as a clone of src. Prefers APFS clonefile with
// CLONE_NOFOLLOW; on cross-device / unsupported errors falls back to exclusive
// byte copy (explicit degraded mode).
func CloneFile(dst, src string) (mechanism string, err error) {
	if dst == "" || src == "" {
		return "", fmt.Errorf("platform: empty clone path")
	}
	if err := unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW); err == nil {
		return CloneMechanismClonefile, nil
	} else if !cloneFallback(err) {
		return "", err
	}
	if err := copyFileExclusive(dst, src); err != nil {
		return "", err
	}
	return CloneMechanismCopy, nil
}

func cloneFallback(err error) bool {
	return errors.Is(err, unix.EXDEV) ||
		errors.Is(err, unix.ENOTSUP) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		os.IsPermission(err)
}
