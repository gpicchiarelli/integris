//go:build darwin

package platform

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCopyTimesPreservesBirthtime(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := unix.Timespec{Sec: 1_600_000_000, Nsec: 0}
	if err := applyBirth(src, sourceTimes{birth: want, hasBirth: true}); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0)
	mt := time.Unix(1_700_000_100, 0)
	if err := os.Chtimes(src, at, mt); err != nil {
		t.Fatal(err)
	}
	if err := CopyTimes(dst, src); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(dst, &st); err != nil {
		t.Fatal(err)
	}
	if st.Btim.Sec != want.Sec {
		t.Fatalf("btim=%d want %d", st.Btim.Sec, want.Sec)
	}
}

func TestCopyFileExclusivePreservesBirthtime(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("clone-btim"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := unix.Timespec{Sec: 1_600_000_500, Nsec: 0}
	if err := applyBirth(src, sourceTimes{birth: want, hasBirth: true}); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_200, 0)
	mt := time.Unix(1_700_000_300, 0)
	if err := os.Chtimes(src, at, mt); err != nil {
		t.Fatal(err)
	}
	if err := copyFileExclusive(dst, src); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(dst, &st); err != nil {
		t.Fatal(err)
	}
	if st.Atim.Sec != at.Unix() || st.Mtim.Sec != mt.Unix() {
		t.Fatalf("atim/mtim=%d/%d want %d/%d", st.Atim.Sec, st.Mtim.Sec, at.Unix(), mt.Unix())
	}
	if st.Btim.Sec != want.Sec {
		t.Fatalf("btim=%d want %d after degraded copy", st.Btim.Sec, want.Sec)
	}
}
