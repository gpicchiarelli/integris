//go:build freebsd

package remotesync

import (
	"os"
	"testing"

	"github.com/gpicchiarelli/integris/internal/launcher"
	"golang.org/x/sys/unix"
)

func TestStageAtAfterCapEnter(t *testing.T) {
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
		t.Fatalf("openLocalStoreAt after CapEnter: %v", err)
	}
	defer store.close()

	payload := []byte("capsicum-m3e-stage")
	dig := digestOf(payload)
	begin := fileBegin{Rel: "c/p.txt", Mode: 0o644, Digest: dig, Size: uint64(len(payload))}
	if _, err := store.beginFile(begin); err != nil {
		t.Fatal(err)
	}
	if err := store.writeChunk(0, payload); err != nil {
		t.Fatal(err)
	}
	if err := store.endFile(begin.Rel, dig); err != nil {
		t.Fatal(err)
	}
	got, _, err := hashAt(store.stageFD, begin.Rel)
	if err != nil {
		t.Fatal(err)
	}
	if got != dig {
		t.Fatalf("digest mismatch")
	}
}
