//go:build unix

package remotesync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/localsync"
	"github.com/gpicchiarelli/integris/internal/remotesync"
	"golang.org/x/sys/unix"
)

func TestOpenAuditSinkAt(t *testing.T) {
	dest := t.TempDir()
	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()

	sink, err := remotesync.OpenAuditSinkAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if _, err := sink.Write([]byte("evt1\n")); err != nil {
		t.Fatal(err)
	}
	_ = sink.Close()

	got, err := os.ReadFile(filepath.Join(dest, localsync.MetaDirName, remotesync.AuditSinkFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "evt1\n" {
		t.Fatalf("got %q", got)
	}

	// Re-open appends.
	sink2, err := remotesync.OpenAuditSinkAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sink2.Close()
	if _, err := sink2.Write([]byte("evt2\n")); err != nil {
		t.Fatal(err)
	}
	_ = sink2.Close()
	got, err = os.ReadFile(filepath.Join(dest, localsync.MetaDirName, remotesync.AuditSinkFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "evt1\nevt2\n" {
		t.Fatalf("got %q", got)
	}
}
