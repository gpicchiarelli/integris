//go:build unix

package localsync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

func TestApplyAtMatchesApply(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m3g")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested")
	if err := os.MkdirAll(filepath.Join(src, "e"), 0o755); err != nil {
		t.Fatal(err)
	}

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

	res, err := localsync.Sync(localsync.Options{
		Source: src, Destination: dst,
		SourceFD: srcDir, DestFD: dstDir,
		DisableJournal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.CompletedOps < 2 {
		t.Fatalf("ops: %+v", res)
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m3g")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested")
}

func TestSyncAtJournaled(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "j.txt"), "journaled-m3g")

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

	res, err := localsync.Sync(localsync.Options{
		Source: src, Destination: dst,
		SourceFD: srcDir, DestFD: dstDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != localsync.OutcomeSuccess {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "j.txt"), "journaled-m3g")
	if _, err := os.Stat(filepath.Join(dst, localsync.MetaDirName, localsync.PlanFileName)); err != nil {
		t.Fatal(err)
	}
}
