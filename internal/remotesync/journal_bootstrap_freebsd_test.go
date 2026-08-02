//go:build freebsd

package remotesync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"github.com/gpicchiarelli/integris/internal/remotesync"
	"golang.org/x/sys/unix"
)

func TestJournalBootstrapAtAfterCapEnter(t *testing.T) {
	dest := t.TempDir()
	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()

	// M3l bootstrap before CapEnter (product journal flow).
	if err := remotesync.BootstrapJournalAt(dir); err != nil {
		t.Fatal(err)
	}

	rights, err := unix.CapRightsInit([]uint64{
		unix.CAP_LOOKUP, unix.CAP_READ, unix.CAP_SEEK, unix.CAP_FSTAT, unix.CAP_FSTATAT,
		unix.CAP_CREATE, unix.CAP_WRITE, unix.CAP_UNLINKAT,
		unix.CAP_MKDIRAT, unix.CAP_FSYNC, unix.CAP_FTRUNCATE,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.CapRightsLimit(dir.Fd(), rights); err != nil {
		t.Fatal(err)
	}
	if err := unix.CapEnter(); err != nil {
		t.Fatal(err)
	}

	jpath := filepath.Join(dest, localsync.MetaDirName, localsync.JournalFileName)
	if _, err := os.OpenFile(jpath, os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		t.Fatal("expected ambient journal bootstrap to fail after CapEnter")
	}

	// Reopen via openat still works (M3f).
	sess := localsync.OpenFileJournalAt(jpath, dir)
	if _, err := sess.Open(); err != nil {
		t.Fatalf("openat journal after CapEnter: %v", err)
	}
	var id codec.TransactionID
	id[0] = 3
	if err := sess.Append(id, codec.TypeObservation, []byte("m3l-bootstrap")); err != nil {
		t.Fatal(err)
	}
	_ = sess.Close()
}
