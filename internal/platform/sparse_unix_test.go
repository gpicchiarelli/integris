//go:build unix

package platform

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCopyFileExclusiveSparseContent(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	const gap int64 = 1 << 20
	f, err := os.OpenFile(src, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("head"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("tail"), gap); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if err := copyFileExclusive(dst, src); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(got)) != gap+4 {
		t.Fatalf("len=%d want %d", len(got), gap+4)
	}
	if string(got[:4]) != "head" {
		t.Fatalf("head=%q", got[:4])
	}
	if string(got[gap:gap+4]) != "tail" {
		t.Fatalf("tail=%q", got[gap:gap+4])
	}

	// Hole preservation is FS-dependent (APFS often materializes after close).
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	srcHole, err := in.Seek(0, unix.SEEK_HOLE)
	if err != nil || !(srcHole > 0 && srcHole < gap) {
		t.Logf("src not holey after close (hole=%d err=%v); skip preserve assert", srcHole, err)
		return
	}
	out, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	dstHole, err := out.Seek(0, unix.SEEK_HOLE)
	if err != nil {
		t.Fatal(err)
	}
	if !(dstHole > 0 && dstHole < gap) {
		t.Fatalf("dst hole=%d; expected sparse hole preserved", dstHole)
	}
}

func TestCopySparseContentsEmpty(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := copySparseContents(out, in); err != nil {
		t.Fatal(err)
	}
}
