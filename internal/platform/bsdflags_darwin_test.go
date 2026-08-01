//go:build darwin

package platform

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCopyBSDFlagsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("f"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("f"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(src, unix.UF_NODUMP); err != nil {
		t.Fatal(err)
	}
	if err := CopyBSDFlags(dst, src); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(dst, &st); err != nil {
		t.Fatal(err)
	}
	if st.Flags&unix.UF_NODUMP == 0 {
		t.Fatalf("dst flags=%#x missing UF_NODUMP", st.Flags)
	}
	_ = unix.Chflags(dst, 0)
	_ = unix.Chflags(src, 0)
}

func TestCopyFileExclusivePreservesBSDFlags(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("clone-flags"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(src, unix.UF_NODUMP); err != nil {
		t.Fatal(err)
	}
	defer unix.Chflags(src, 0)
	if err := copyFileExclusive(dst, src); err != nil {
		t.Fatal(err)
	}
	defer unix.Chflags(dst, 0)
	var st unix.Stat_t
	if err := unix.Stat(dst, &st); err != nil {
		t.Fatal(err)
	}
	if st.Flags&unix.UF_NODUMP == 0 {
		t.Fatalf("dst flags=%#x missing UF_NODUMP after degraded copy", st.Flags)
	}
}
