//go:build freebsd

package localsync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

func TestJournalAtAfterCapEnter(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	dest := t.TempDir()
	// Pre-create ambient so we can contrast reopen after CapEnter.
	jpath := filepath.Join(dest, localsync.MetaDirName, localsync.JournalFileName)
	if err := os.MkdirAll(filepath.Dir(jpath), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(jpath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()

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

	if _, err := os.Lstat(jpath); err == nil {
		t.Fatal("expected ambient Lstat to fail after CapEnter")
	}
	ambient := localsync.OpenFileJournal(jpath)
	if _, err := ambient.Open(); err == nil {
		t.Fatal("expected ambient journal Open to fail after CapEnter")
	}

	sess := localsync.OpenFileJournalAt(jpath, dir)
	prefix, err := sess.Open()
	if err != nil {
		t.Fatalf("openat journal after CapEnter: %v", err)
	}
	_ = prefix
	var id codec.TransactionID
	id[0] = 2
	if err := sess.Append(id, codec.TypeObservation, []byte("capsicum-m3f")); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen again under CapEnter.
	sess2 := localsync.OpenFileJournalAt(jpath, dir)
	prefix2, err := sess2.Open()
	if err != nil {
		t.Fatal(err)
	}
	if prefix2.Bytes <= 0 {
		t.Fatal("expected durable prefix")
	}
	_ = sess2.Close()
}
