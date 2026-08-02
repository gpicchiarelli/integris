//go:build freebsd

package localsync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

func TestScanAtAfterCapEnter(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "cap.txt"), "capsicum-scanat")

	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), root)
	defer dir.Close()

	rights, err := unix.CapRightsInit([]uint64{
		unix.CAP_LOOKUP, unix.CAP_READ, unix.CAP_SEEK, unix.CAP_FSTAT, unix.CAP_FSTATAT,
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

	if _, err := os.Lstat(root); err == nil {
		t.Fatal("expected ambient Lstat to fail after CapEnter")
	}
	if _, err := localsync.Scan(root); err == nil {
		t.Fatal("expected ambient Scan to fail after CapEnter")
	}

	man, err := localsync.ScanAt(dir, root)
	if err != nil {
		t.Fatalf("ScanAt after CapEnter: %v", err)
	}
	if len(man.Entries) != 1 || man.Entries[0].Rel != "cap.txt" {
		t.Fatalf("%+v", man.Entries)
	}
}
