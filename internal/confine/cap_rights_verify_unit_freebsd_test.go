//go:build freebsd

package confine

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVerifyCapRightsLimitedRejectsUnlimited(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "f"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	want := []uint64{unix.CAP_READ, unix.CAP_WRITE, unix.CAP_EVENT}
	absent := []uint64{unix.CAP_FEXECVE}
	err = verifyCapRightsLimited(f.Fd(), want, absent)
	if err == nil {
		t.Fatal("expected refusal on unlimited FD (sentinel still set)")
	}
}
