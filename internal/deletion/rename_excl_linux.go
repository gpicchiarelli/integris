//go:build linux

package deletion

import "golang.org/x/sys/unix"

func renameExclusive(fromDir, toDir int, fromName, toName string) error {
	return unix.Renameat2(fromDir, fromName, toDir, toName, unix.RENAME_NOREPLACE)
}
