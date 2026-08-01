package confine

import (
	"os"
	"path/filepath"
	"runtime"
)

// NegativeFSOpen attempts to create a new file after ApplyEngineering.
// On Linux/OpenBSD/FreeBSD with apply succeeding, this should be denied.
// Safe to call from engineering children only (not the test process on Linux).
func NegativeFSOpen() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	dir := os.TempDir()
	p := filepath.Join(dir, "integris-neg-fs-probe")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err == nil {
		_ = f.Close()
		_ = os.Remove(p)
		return Finding{
			ID: "NEG-FS-OPEN", Platform: plat, Control: "filesystem_writes",
			Status: StatusUnexpectedAllow, Detail: "new file create succeeded after apply",
		}
	}
	return Finding{
		ID: "NEG-FS-OPEN", Platform: plat, Control: "filesystem_writes",
		Status: StatusDeniedExpected, Detail: err.Error(),
	}
}
