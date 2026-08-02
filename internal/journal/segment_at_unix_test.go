//go:build unix

package journal_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/journal"
	"golang.org/x/sys/unix"
)

func TestOpenFileSegmentAt(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)

	seg, err := journal.OpenFileSegmentAt(fd, "local.jrn")
	if err != nil {
		t.Fatal(err)
	}
	defer seg.Close()
	if err := seg.Append([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := seg.Sync(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "local.jrn"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Fatalf("got %q", got)
	}
}
