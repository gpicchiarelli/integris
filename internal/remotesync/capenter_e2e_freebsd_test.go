//go:build freebsd

package remotesync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

// TestReceiveOpenatChainAfterCapEnter is the M3i CapEnter proof: ambient path
// ops fail, while stage → ScanAt → journaled SyncAt publish → held audit sink
// succeed under one capability-mode session.
func TestReceiveOpenatChainAfterCapEnter(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	dest := t.TempDir()
	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()

	// Audit sink bootstrap before CapEnter (M3h); held across capability mode.
	sink, err := OpenAuditSinkAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	rights, err := unix.CapRightsInit([]uint64{
		unix.CAP_LOOKUP, unix.CAP_READ, unix.CAP_SEEK, unix.CAP_FSTAT, unix.CAP_FSTATAT,
		unix.CAP_CREATE, unix.CAP_WRITE, unix.CAP_UNLINKAT,
		unix.CAP_MKDIRAT, unix.CAP_RENAMEAT_SOURCE, unix.CAP_RENAMEAT_TARGET,
		unix.CAP_FSYNC, unix.CAP_FCHMOD, unix.CAP_FCHMODAT, unix.CAP_FTRUNCATE,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.CapRightsLimit(dir.Fd(), rights); err != nil {
		t.Fatal(err)
	}
	launcher.SkipSubprocessCleanupOnSuccess(t)
	if err := unix.CapEnter(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(dest); err == nil {
		t.Fatal("expected ambient Lstat to fail after CapEnter")
	}
	if _, err := openLocalStoreAmbient(dest); err == nil {
		t.Fatal("expected ambient store open to fail after CapEnter")
	}

	store, err := openLocalStoreAt(dest, dir)
	if err != nil {
		t.Fatalf("stage openat: %v", err)
	}
	defer store.close()

	payload := []byte("capsicum-m3i-e2e")
	dig := digestOf(payload)
	begin := fileBegin{Rel: "pub/e2e.txt", Mode: 0o644, Digest: dig, Size: uint64(len(payload))}
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
		t.Fatalf("ScanAt: %v", err)
	}
	store.setDestManifest(man.Entries)

	jpath := filepath.Join(dest, localsync.MetaDirName, localsync.JournalFileName)
	if _, err := localsync.OpenFileJournal(jpath).Open(); err == nil {
		t.Fatal("expected ambient journal Open to fail after CapEnter")
	}
	j := localsync.OpenFileJournalAt(jpath, dir)
	if err := store.commit(j); err != nil {
		t.Fatalf("commit under CapEnter: %v", err)
	}

	if _, err := sink.Write([]byte("m3i-audit\n")); err != nil {
		t.Fatalf("held audit sink write: %v", err)
	}

	// Verify published content via openat (ambient ReadFile fails).
	pfd, err := unix.Openat(int(dir.Fd()), "pub", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pfd)
	ffd, err := unix.Openat(pfd, "e2e.txt", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(ffd), "e2e.txt")
	buf := make([]byte, 64)
	n, rerr := f.Read(buf)
	_ = f.Close()
	if rerr != nil && n == 0 {
		t.Fatal(rerr)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("published %q", buf[:n])
	}
}
