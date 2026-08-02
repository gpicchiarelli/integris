//go:build unix

package remotesync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

// TestReceiveOpenatChain exercises stage → journaled publish → audit sink via
// conferred FDs (M3i wiring proof for non-FreeBSD CI; no CapEnter).
func TestReceiveOpenatChain(t *testing.T) {
	dest := t.TempDir()
	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()

	sink, err := OpenAuditSinkAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	store, err := openLocalStoreAt(dest, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()

	payload := []byte("m3i-openat-chain")
	dig := digestOf(payload)
	begin := fileBegin{Rel: "pub/a.txt", Mode: 0o644, Digest: dig, Size: uint64(len(payload))}
	if _, err := store.beginFile(begin); err != nil {
		t.Fatal(err)
	}
	if err := store.writeChunk(0, payload); err != nil {
		t.Fatal(err)
	}
	if err := store.endFile(begin.Rel, dig); err != nil {
		t.Fatal(err)
	}

	man, err := localsync.ScanAt(dir, dest)
	if err != nil {
		t.Fatal(err)
	}
	store.setDestManifest(man.Entries)

	jpath := filepath.Join(dest, localsync.MetaDirName, localsync.JournalFileName)
	j := localsync.OpenFileJournalAt(jpath, dir)
	if err := store.commit(j); err != nil {
		t.Fatal(err)
	}
	if _, err := sink.Write([]byte("audit-ok\n")); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "pub", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("published %q", got)
	}
	if _, err := os.Stat(filepath.Join(dest, localsync.MetaDirName, localsync.PlanFileName)); err != nil {
		t.Fatal(err)
	}
	audit, err := os.ReadFile(filepath.Join(dest, localsync.MetaDirName, AuditSinkFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(audit) != "audit-ok\n" {
		t.Fatalf("audit %q", audit)
	}
}
