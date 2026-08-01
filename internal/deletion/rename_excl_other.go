//go:build unix && !linux && !darwin

package deletion

import "golang.org/x/sys/unix"

// Fallback: renameat without exclusive flag, preceded by caller existence check.
func renameExclusive(fromDir, toDir int, fromName, toName string) error {
	return unix.Renameat(fromDir, fromName, toDir, toName)
}
