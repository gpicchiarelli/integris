//go:build unix

package localsync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

func TestScanAtMatchesScan(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "hello-scanat")
	mustWrite(t, filepath.Join(root, "d", "b.txt"), "nested")
	if err := os.MkdirAll(filepath.Join(root, ".integris"), 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, ".integris", "local.jrn"), "meta")

	want, err := localsync.Scan(root)
	if err != nil {
		t.Fatal(err)
	}

	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), root)
	defer dir.Close()

	got, err := localsync.ScanAt(dir, root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Root != root {
		t.Fatalf("root %q", got.Root)
	}
	if len(got.Entries) != len(want.Entries) {
		t.Fatalf("entries got %d want %d\ngot=%+v\nwant=%+v", len(got.Entries), len(want.Entries), got.Entries, want.Entries)
	}
	for i := range want.Entries {
		if got.Entries[i] != want.Entries[i] {
			t.Fatalf("entry[%d] got %+v want %+v", i, got.Entries[i], want.Entries[i])
		}
	}
}

func TestScanAtRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "real.txt"), "x")
	if err := os.Symlink("real.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), root)
	defer dir.Close()

	_, err = localsync.ScanAt(dir, root)
	if err == nil || !localsync.IsKind(err, localsync.KindUnsupported) {
		t.Fatalf("got %v", err)
	}
}
