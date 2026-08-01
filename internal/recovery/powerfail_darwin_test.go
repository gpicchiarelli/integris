//go:build darwin

package recovery_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/platform"
)

const powerfailMarker = "integris-powerfail-marker-v1"

// TestPowerFailAbruptDetachSyncFileSurvive proves platform.SyncFile (Darwin
// F_FULLFSYNC) keeps a marker across hdiutil force-detach + remount — a thin
// power-fail / volume-teardown proxy for EVD-RECOVERY.
//
// The unflushed differential (write without SyncFile should be lost) is
// attempted when possible; many hosts flush the .dmg backing store before
// detach, in which case that arm is skipped rather than failed.
func TestPowerFailAbruptDetachSyncFileSurvive(t *testing.T) {
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skip("hdiutil not available")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "integris-powerfail.dmg")
	mnt := filepath.Join(dir, "mnt")
	if err := os.Mkdir(mnt, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("hdiutil", "create",
		"-size", "4m", "-fs", "HFS+", "-volname", "INTEGRISPF", "-ov", img,
	).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create: %v (%s)", err, out)
	}

	attach := func() {
		t.Helper()
		if out, err := exec.Command("hdiutil", "attach", img, "-nobrowse", "-mountpoint", mnt).CombinedOutput(); err != nil {
			t.Skipf("hdiutil attach: %v (%s)", err, out)
		}
	}
	detach := func() {
		t.Helper()
		_ = exec.Command("hdiutil", "detach", mnt, "-force").Run()
	}

	// Arm B (required): SyncFile then abrupt detach → marker survives.
	attach()
	synced := filepath.Join(mnt, "synced")
	f, err := os.OpenFile(synced, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		detach()
		t.Fatal(err)
	}
	if _, err := f.WriteString(powerfailMarker); err != nil {
		_ = f.Close()
		detach()
		t.Fatal(err)
	}
	if err := platform.SyncFile(f); err != nil {
		_ = f.Close()
		detach()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		detach()
		t.Fatal(err)
	}
	detach()
	attach()
	got, err := os.ReadFile(synced)
	detach()
	if err != nil {
		t.Fatalf("synced marker missing after SyncFile+force-detach: %v", err)
	}
	if string(got) != powerfailMarker {
		t.Fatalf("synced marker=%q want %q", got, powerfailMarker)
	}

	// Arm A (differential): write without SyncFile; expect loss when the host
	// does not flush the image backing store before detach.
	attach()
	unsynced := filepath.Join(mnt, "unsynced")
	f, err = os.OpenFile(unsynced, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		detach()
		t.Fatal(err)
	}
	if _, err := f.WriteString(powerfailMarker); err != nil {
		_ = f.Close()
		detach()
		t.Fatal(err)
	}
	// Close releases the FD but deliberately skips SyncFile / F_FULLFSYNC.
	if err := f.Close(); err != nil {
		detach()
		t.Fatal(err)
	}
	detach()
	attach()
	got, err = os.ReadFile(unsynced)
	detach()
	if err != nil || string(got) != powerfailMarker {
		// Lost or truncated — differential observed.
		t.Log("unflushed-loss differential observed after force-detach")
		return
	}
	t.Log("unflushed-loss differential unavailable: host flushed .dmg before force-detach; SyncFile survive arm passed")
}
