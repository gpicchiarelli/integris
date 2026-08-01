//go:build !unix

package platform

import (
	"fmt"
	"os"
)

// SyncFile persists file data and metadata via os.File.Sync.
func SyncFile(f *os.File) error {
	if f == nil {
		return fmt.Errorf("platform: nil file")
	}
	return f.Sync()
}

// DurabilityMechanism names the SyncFile primitive for this build.
func DurabilityMechanism() string { return "File.Sync" }
