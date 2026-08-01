//go:build darwin

package platform

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// SyncFile persists file data and metadata with Darwin F_FULLFSYNC (stronger
// than fsync/os.File.Sync on APFS/HFS+ for media barrier semantics).
func SyncFile(f *os.File) error {
	if f == nil {
		return fmt.Errorf("platform: nil file")
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0); err != nil {
		return err
	}
	return nil
}

// DurabilityMechanism names the SyncFile primitive for this build.
func DurabilityMechanism() string { return "F_FULLFSYNC" }
