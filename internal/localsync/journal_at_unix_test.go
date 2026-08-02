//go:build unix

package localsync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

func TestOpenFileJournalAtReopen(t *testing.T) {
	dest := t.TempDir()
	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()

	jpath := filepath.Join(dest, localsync.MetaDirName, localsync.JournalFileName)
	sess := localsync.OpenFileJournalAt(jpath, dir)

	prefix, err := sess.Open()
	if err != nil {
		t.Fatal(err)
	}
	if prefix.Bytes != 0 {
		t.Fatalf("expected empty prefix, got %d", prefix.Bytes)
	}
	var id codec.TransactionID
	id[0] = 1
	if err := sess.Append(id, codec.TypeObservation, []byte("m3f-at")); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen via openat (same conferred FD).
	sess2 := localsync.OpenFileJournalAt(jpath, dir)
	prefix2, err := sess2.Open()
	if err != nil {
		t.Fatal(err)
	}
	if prefix2.Bytes <= 0 {
		t.Fatal("expected durable prefix after append")
	}
	raw, err := localsync.AcceptedPrefixBytes(sess2, prefix2.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(raw)) != prefix2.Bytes {
		t.Fatalf("prefix bytes %d != %d", len(raw), prefix2.Bytes)
	}
	_ = sess2.Close()

	if _, err := os.Stat(jpath); err != nil {
		t.Fatal(err)
	}
}
