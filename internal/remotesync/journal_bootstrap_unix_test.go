//go:build unix

package remotesync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/localsync"
	"github.com/gpicchiarelli/integris/internal/remotesync"
	"golang.org/x/sys/unix"
)

func TestBootstrapJournalAt(t *testing.T) {
	dest := t.TempDir()
	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()

	if err := remotesync.BootstrapJournalAt(dir); err != nil {
		t.Fatal(err)
	}
	jpath := filepath.Join(dest, localsync.MetaDirName, localsync.JournalFileName)
	if _, err := os.Stat(jpath); err != nil {
		t.Fatal(err)
	}
	// Idempotent.
	if err := remotesync.BootstrapJournalAt(dir); err != nil {
		t.Fatal(err)
	}
}
