package confine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// NegativeEngineering runs in-child OS denial probes after ApplyEngineering.
// Does not cover role-semantic NegativeBaseline IDs.
func NegativeEngineering() []Finding {
	return []Finding{NegativeFSOpen(), NegativeExec(), NegativePtrace()}
}

// FormatNegativeAck appends |NEG-FS:…|NEG-EXEC:…|NEG-PTRACE:… tokens for stub IPC.
func FormatNegativeAck(findings []Finding) string {
	var b strings.Builder
	for _, f := range findings {
		switch f.ID {
		case "NEG-FS-OPEN":
			b.WriteString("|NEG-FS:")
		case "NEG-EXEC":
			b.WriteString("|NEG-EXEC:")
		case "NEG-PTRACE":
			b.WriteString("|NEG-PTRACE:")
		default:
			continue
		}
		b.WriteString(string(f.Status))
	}
	return b.String()
}
