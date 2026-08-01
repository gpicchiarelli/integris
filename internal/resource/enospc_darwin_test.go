//go:build darwin

package resource_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestENOSPCFullVolumeHarness fills a tiny fixed-size HFS+ disk image until
// writes return unix.ENOSPC. Uses hdiutil (test-only os/exec); skips if create
// or attach fails (CI hosts without disk-image privileges).
func TestENOSPCFullVolumeHarness(t *testing.T) {
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skip("hdiutil not available")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "integris-enospc.dmg")
	mnt := filepath.Join(dir, "mnt")
	if err := os.Mkdir(mnt, 0o700); err != nil {
		t.Fatal(err)
	}

	create := exec.Command("hdiutil", "create",
		"-size", "2m",
		"-fs", "HFS+",
		"-volname", "INTEGRISENOSPC",
		"-ov",
		img,
	)
	if out, err := create.CombinedOutput(); err != nil {
		t.Skipf("hdiutil create: %v (%s)", err, out)
	}

	attach := exec.Command("hdiutil", "attach", img, "-nobrowse", "-mountpoint", mnt)
	if out, err := attach.CombinedOutput(); err != nil {
		t.Skipf("hdiutil attach: %v (%s)", err, out)
	}
	defer func() {
		detach := exec.Command("hdiutil", "detach", mnt, "-force")
		_ = detach.Run()
	}()

	path := filepath.Join(mnt, "fill")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	buf := make([]byte, 64<<10)
	var wrote int
	sawENOSPC := false
	for i := 0; i < 512; i++ {
		n, err := f.Write(buf)
		wrote += n
		if err == nil {
			continue
		}
		if errors.Is(err, unix.ENOSPC) {
			sawENOSPC = true
			break
		}
		t.Fatalf("unexpected write error after %d bytes: %v", wrote, err)
	}
	if !sawENOSPC {
		t.Fatalf("expected ENOSPC after filling 2MiB volume; wrote %d bytes", wrote)
	}
	if wrote == 0 {
		t.Fatal("ENOSPC with zero successful writes")
	}
}
