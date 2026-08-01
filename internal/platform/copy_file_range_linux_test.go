//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyFileRangeAllRoundTrip(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src")
	dstPath := filepath.Join(dir, "dst")
	payload := []byte("copy-file-range-payload-v1")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(dstPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if err := copyFileRangeAll(dst, src); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}
