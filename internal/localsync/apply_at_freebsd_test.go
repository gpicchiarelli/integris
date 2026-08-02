//go:build freebsd

package localsync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

func TestApplyAtAfterCapEnter(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "cap.txt"), "capsicum-m3g-publish")

	srcFD, err := unix.Open(src, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dstFD, err := unix.Open(dst, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	srcDir := os.NewFile(uintptr(srcFD), src)
	dstDir := os.NewFile(uintptr(dstFD), dst)
	defer srcDir.Close()
	defer dstDir.Close()

	ro, err := unix.CapRightsInit([]uint64{
		unix.CAP_LOOKUP, unix.CAP_READ, unix.CAP_SEEK, unix.CAP_FSTAT, unix.CAP_FSTATAT,
	})
	if err != nil {
		t.Fatal(err)
	}
	rw, err := unix.CapRightsInit([]uint64{
		unix.CAP_LOOKUP, unix.CAP_READ, unix.CAP_SEEK, unix.CAP_FSTAT, unix.CAP_FSTATAT,
		unix.CAP_CREATE, unix.CAP_WRITE, unix.CAP_UNLINKAT,
		unix.CAP_MKDIRAT, unix.CAP_RENAMEAT_SOURCE, unix.CAP_RENAMEAT_TARGET,
		unix.CAP_FSYNC, unix.CAP_FCHMOD, unix.CAP_FCHMODAT, unix.CAP_FTRUNCATE,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.CapRightsLimit(srcDir.Fd(), ro); err != nil {
		t.Fatal(err)
	}
	if err := unix.CapRightsLimit(dstDir.Fd(), rw); err != nil {
		t.Fatal(err)
	}
	if err := unix.CapEnter(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(src); err == nil {
		t.Fatal("expected ambient Lstat to fail after CapEnter")
	}
	if _, err := localsync.Sync(localsync.Options{
		Source: src, Destination: dst, DisableJournal: true,
	}); err == nil {
		t.Fatal("expected ambient Sync to fail after CapEnter")
	}

	res, err := localsync.Sync(localsync.Options{
		Source: src, Destination: dst,
		SourceFD: srcDir, DestFD: dstDir,
		DisableJournal: true,
	})
	if err != nil {
		t.Fatalf("SyncAt after CapEnter: %v", err)
	}
	if res.CompletedOps < 1 {
		t.Fatalf("%+v", res)
	}

	// Verify published bytes via openat (ambient ReadFile fails).
	fd, err := unix.Openat(int(dstDir.Fd()), "cap.txt", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "cap.txt")
	got := make([]byte, 64)
	n, err := f.Read(got)
	_ = f.Close()
	if err != nil && n == 0 {
		t.Fatal(err)
	}
	if string(got[:n]) != "capsicum-m3g-publish" {
		t.Fatalf("got %q", got[:n])
	}
}
