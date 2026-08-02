package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunSyncOK(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	code := run([]string{"sync", "-source", src, "-destination", dst})
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	b, err := os.ReadFile(filepath.Join(dst, "f.txt"))
	if err != nil || string(b) != "ok" {
		t.Fatalf("dst=%q err=%v", b, err)
	}
}

func TestRunSyncUsage(t *testing.T) {
	if code := run(nil); code != exitUsage {
		t.Fatalf("got %d", code)
	}
	if code := run([]string{"sync"}); code != exitUsage {
		t.Fatalf("got %d", code)
	}
}

func TestRunSyncSamePath(t *testing.T) {
	dir := t.TempDir()
	code := run([]string{"sync", "-source", dir, "-destination", dir})
	if code != exitPathUnsafe {
		t.Fatalf("got %d", code)
	}
}
