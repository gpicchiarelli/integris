//go:build darwin

package deletion

import "golang.org/x/sys/unix"

func renameExclusive(fromDir, toDir int, fromName, toName string) error {
	return unix.RenameatxNp(fromDir, fromName, toDir, toName, unix.RENAME_EXCL)
}
