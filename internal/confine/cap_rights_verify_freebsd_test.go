//go:build freebsd

package confine_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gpicchiarelli/integris/internal/confine"
	"golang.org/x/sys/unix"
)

func TestLimitConferredFDsCapRightsGetVerify(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "pipe"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	before, err := unix.CapRightsGet(f.Fd())
	if err != nil {
		t.Fatal(err)
	}
	execSet, err := unix.CapRightsIsSet(before, []uint64{unix.CAP_FEXECVE})
	if err != nil {
		t.Fatal(err)
	}
	if !execSet {
		t.Fatal("precondition: unlimited FD should include CAP_FEXECVE")
	}

	ok := confine.LimitConferredFDs(f)
	if ok.Status != confine.StatusAvailable {
		t.Fatalf("limit: %+v", ok)
	}
	if !strings.Contains(ok.Detail, "CapRightsGet verified") {
		t.Fatalf("detail missing CapRightsGet verified: %q", ok.Detail)
	}

	after, err := unix.CapRightsGet(f.Fd())
	if err != nil {
		t.Fatal(err)
	}
	wantOK, err := unix.CapRightsIsSet(after, []uint64{unix.CAP_READ, unix.CAP_WRITE, unix.CAP_EVENT})
	if err != nil {
		t.Fatal(err)
	}
	if !wantOK {
		t.Fatal("expected CAP_READ|WRITE|EVENT after limit")
	}
	execSet, err = unix.CapRightsIsSet(after, []uint64{unix.CAP_FEXECVE})
	if err != nil {
		t.Fatal(err)
	}
	if execSet {
		t.Fatal("CAP_FEXECVE should be absent after conferred limit")
	}
	for _, right := range []uint64{unix.CAP_FCNTL, unix.CAP_IOCTL} {
		set, err := unix.CapRightsIsSet(after, []uint64{right})
		if err != nil {
			t.Fatal(err)
		}
		if set {
			t.Fatalf("0x%x should be absent after conferred limit (M6b)", right)
		}
	}
}

func TestLimitAllowRootFDsReadonlyClearsWrite(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Open(filepath.Clean(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ok := confine.LimitAllowRootFDs(confine.ArchiveFSReadonly, f)
	if ok.Status != confine.StatusAvailable {
		t.Fatalf("limit: %+v", ok)
	}
	after, err := unix.CapRightsGet(f.Fd())
	if err != nil {
		t.Fatal(err)
	}
	writeSet, err := unix.CapRightsIsSet(after, []uint64{unix.CAP_WRITE})
	if err != nil {
		t.Fatal(err)
	}
	if writeSet {
		t.Fatal("CAP_WRITE should be absent on readonly allow-root")
	}
	for _, right := range []uint64{unix.CAP_FCNTL, unix.CAP_IOCTL} {
		set, err := unix.CapRightsIsSet(after, []uint64{right})
		if err != nil {
			t.Fatal(err)
		}
		if set {
			t.Fatalf("0x%x should be absent on readonly allow-root (M6b)", right)
		}
	}
}

func TestLimitAllowRootFDsReadWriteClearsFcntlIoctl(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Open(filepath.Clean(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ok := confine.LimitAllowRootFDs(confine.ArchiveFSReadWrite, f)
	if ok.Status != confine.StatusAvailable {
		t.Fatalf("limit: %+v", ok)
	}
	after, err := unix.CapRightsGet(f.Fd())
	if err != nil {
		t.Fatal(err)
	}
	for _, right := range []uint64{unix.CAP_FCNTL, unix.CAP_IOCTL} {
		set, err := unix.CapRightsIsSet(after, []uint64{right})
		if err != nil {
			t.Fatal(err)
		}
		if set {
			t.Fatalf("0x%x should be absent on readwrite allow-root (M6b)", right)
		}
	}
}
