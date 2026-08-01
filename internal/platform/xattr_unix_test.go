//go:build unix && !openbsd

package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func probeXattrKey() string {
	if runtime.GOOS == "linux" {
		return "user.integris.probe"
	}
	return "integris.probe"
}

func TestCopyXattrRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := probeXattrKey()
	want := []byte("probe-v1")
	if err := unix.Setxattr(src, key, want, 0); err != nil {
		t.Skipf("xattr unsupported on this filesystem: %v", err)
	}
	if err := CopyXattr(dst, src); err != nil {
		t.Fatal(err)
	}
	got, err := getXattr(dst, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCopyXattrNoOpWithoutSourceAttrs(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CopyXattr(dst, src); err != nil {
		t.Fatal(err)
	}
}

func TestCopyFileExclusivePreservesXattr(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("clone-xattr"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := probeXattrKey()
	want := []byte("keep")
	if err := unix.Setxattr(src, key, want, 0); err != nil {
		t.Skipf("xattr unsupported on this filesystem: %v", err)
	}
	if err := copyFileExclusive(dst, src); err != nil {
		t.Fatal(err)
	}
	gotPayload, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotPayload) != "clone-xattr" {
		t.Fatalf("payload=%q", gotPayload)
	}
	got, err := getXattr(dst, key)
	if err != nil {
		t.Fatalf("dst xattr missing: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
}
