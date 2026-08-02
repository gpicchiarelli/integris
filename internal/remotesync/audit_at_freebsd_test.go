//go:build freebsd

package remotesync_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"github.com/gpicchiarelli/integris/internal/remotesync"
	"golang.org/x/sys/unix"
)

func TestAuditSinkAtAfterCapEnter(t *testing.T) {
	if !launcher.InTestSubprocess(t) {
		return
	}
	dest := t.TempDir()
	fd, err := unix.Open(dest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(fd), dest)
	defer dir.Close()

	// Bootstrap sink via openat before CapEnter (product audit flow).
	sink, err := remotesync.OpenAuditSinkAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	// Readonly rights on dest root (Audit archive mode); sink FD stays writable.
	rights, err := unix.CapRightsInit([]uint64{
		unix.CAP_LOOKUP, unix.CAP_READ, unix.CAP_SEEK, unix.CAP_FSTAT, unix.CAP_FSTATAT,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.CapRightsLimit(dir.Fd(), rights); err != nil {
		t.Fatal(err)
	}
	if err := unix.CapEnter(); err != nil {
		t.Fatal(err)
	}

	sinkPath := filepath.Join(dest, localsync.MetaDirName, remotesync.AuditSinkFileName)
	if _, err := os.OpenFile(sinkPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		t.Fatal("expected ambient sink open to fail after CapEnter")
	}
	if _, err := remotesync.OpenAuditSinkAt(dir); err == nil {
		t.Fatal("expected openat recreate under readonly allow-root to fail after CapEnter")
	}

	if _, err := sink.Write([]byte("capsicum-m3h\n")); err != nil {
		t.Fatalf("held sink write after CapEnter: %v", err)
	}
}
