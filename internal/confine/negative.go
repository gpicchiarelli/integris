package confine

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// NegativeFSOpen attempts to create a new file after ApplyEngineering.
// On Linux/OpenBSD/FreeBSD/Darwin with apply succeeding, this should be denied.
// Safe to call from engineering children only (not the test process on Linux).
func NegativeFSOpen() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	dir := os.TempDir()
	p := filepath.Join(dir, "integris-neg-fs-probe")
	if runtime.GOOS == "openbsd" {
		// O_CREATE without wpath aborts under pledge; probe unveil deny via open.
		_, err := os.Open(p)
		if err == nil {
			return Finding{
				ID: "NEG-FS-OPEN", Platform: plat, Control: "filesystem_writes",
				Status: StatusUnexpectedAllow, Detail: "path open of non-unveiled temp succeeded after apply",
			}
		}
		return Finding{
			ID: "NEG-FS-OPEN", Platform: plat, Control: "filesystem_writes",
			Status: StatusDeniedExpected, Detail: "unveil/path: " + err.Error(),
		}
	}
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

// NegativeFSRead attempts a path-based open of a well-known file after apply.
// Landlock empty ruleset, locked unveil, Capsicum, and Darwin Seatbelt (no
// ambient file-read-data) should deny it; conferred FDs remain readable.
func NegativeFSRead() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	switch runtime.GOOS {
	case "linux", "openbsd", "freebsd", "darwin":
	default:
		return Finding{
			ID: "NEG-FS-READ", Platform: plat, Control: "filesystem_reads",
			Status: StatusSkipped, Detail: "no engineering path-read denylist on this OS",
		}
	}
	f, err := os.Open("/etc/hosts")
	if err == nil {
		_ = f.Close()
		return Finding{
			ID: "NEG-FS-READ", Platform: plat, Control: "filesystem_reads",
			Status: StatusUnexpectedAllow, Detail: "path open /etc/hosts succeeded after apply",
		}
	}
	return Finding{
		ID: "NEG-FS-READ", Platform: plat, Control: "filesystem_reads",
		Status: StatusDeniedExpected, Detail: err.Error(),
	}
}

// NegativeFSPath attempts to open a conferred allow-root after apply.
// Expected StatusAvailable when RoleArchiveFSMode is non-none and roots were
// installed; otherwise skipped. On FreeBSD, uses a conferred directory FD.
func NegativeFSPath(role authority.ProcessRole, opts ApplyOptions) Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	mode := RoleArchiveFSMode(role)
	roots := opts.AllowRoots
	if mode == ArchiveFSNone || len(roots) == 0 {
		return Finding{
			ID: "NEG-FS-PATH", Platform: plat, Control: "path_allow_list",
			Status: StatusSkipped, Detail: "no archive allow-roots for role",
		}
	}
	switch runtime.GOOS {
	case "linux", "openbsd", "darwin":
	case "freebsd":
		if err := probeAllowRootReadable(opts); err != nil {
			return Finding{
				ID: "NEG-FS-PATH", Platform: plat, Control: "path_allow_list",
				Status: StatusUnavailable, Detail: "allow-root fd probe failed: " + err.Error(),
			}
		}
		return Finding{
			ID: "NEG-FS-PATH", Platform: plat, Control: "path_allow_list",
			Status: StatusAvailable, Detail: "allow-root fd fstat ok mode=" + archiveModeLabel(mode),
		}
	default:
		return Finding{
			ID: "NEG-FS-PATH", Platform: plat, Control: "path_allow_list",
			Status: StatusSkipped, Detail: "no path allow-list on this OS",
		}
	}
	norm, err := NormalizeAllowRoots(roots)
	if err != nil || len(norm) == 0 {
		detail := "normalize failed"
		if err != nil {
			detail = err.Error()
		}
		return Finding{
			ID: "NEG-FS-PATH", Platform: plat, Control: "path_allow_list",
			Status: StatusUnavailable, Detail: detail,
		}
	}
	f, err := os.Open(norm[0])
	if err != nil {
		return Finding{
			ID: "NEG-FS-PATH", Platform: plat, Control: "path_allow_list",
			Status: StatusUnavailable, Detail: "allow-root open failed: " + err.Error(),
		}
	}
	_ = f.Close()
	return Finding{
		ID: "NEG-FS-PATH", Platform: plat, Control: "path_allow_list",
		Status: StatusAvailable, Detail: "allow-root open ok mode=" + archiveModeLabel(mode),
	}
}

// NegativeFSPathWrite attempts create/write under a conferred allow-root.
// ArchiveFSReadonly roles must be denied; ArchiveFSReadWrite must succeed.
// On FreeBSD, uses openat on a conferred directory FD.
func NegativeFSPathWrite(role authority.ProcessRole, opts ApplyOptions) Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	mode := RoleArchiveFSMode(role)
	roots := opts.AllowRoots
	if mode == ArchiveFSNone || len(roots) == 0 {
		return Finding{
			ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
			Status: StatusSkipped, Detail: "no archive allow-roots for role",
		}
	}
	switch runtime.GOOS {
	case "linux", "openbsd", "darwin":
	case "freebsd":
		cleanup, err := probeAllowRootCreate(opts)
		if mode == ArchiveFSReadonly {
			if err == nil {
				if cleanup != nil {
					cleanup()
				}
				return Finding{
					ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
					Status: StatusUnexpectedAllow, Detail: "create under readonly allow-root fd succeeded",
				}
			}
			return Finding{
				ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
				Status: StatusDeniedExpected, Detail: err.Error(),
			}
		}
		if err != nil {
			return Finding{
				ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
				Status: StatusUnavailable, Detail: "create under readwrite allow-root fd failed: " + err.Error(),
			}
		}
		if cleanup != nil {
			cleanup()
		}
		return Finding{
			ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
			Status: StatusAvailable, Detail: "allow-root fd write ok mode=readwrite",
		}
	default:
		return Finding{
			ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
			Status: StatusSkipped, Detail: "no path allow-list on this OS",
		}
	}
	norm, err := NormalizeAllowRoots(roots)
	if err != nil || len(norm) == 0 {
		detail := "normalize failed"
		if err != nil {
			detail = err.Error()
		}
		return Finding{
			ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
			Status: StatusUnavailable, Detail: detail,
		}
	}
	p := filepath.Join(norm[0], "integris-neg-fs-write")
	if runtime.GOOS == "openbsd" && mode == ArchiveFSReadonly {
		// O_CREATE/O_WRONLY without wpath aborts under pledge.
		return Finding{
			ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
			Status: StatusDeniedExpected, Detail: "pledge omits wpath for readonly archive role",
		}
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if mode == ArchiveFSReadonly {
		if err == nil {
			_ = f.Close()
			_ = os.Remove(p)
			return Finding{
				ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
				Status: StatusUnexpectedAllow, Detail: "create under readonly allow-root succeeded",
			}
		}
		return Finding{
			ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
			Status: StatusDeniedExpected, Detail: err.Error(),
		}
	}
	if err != nil {
		return Finding{
			ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
			Status: StatusUnavailable, Detail: "create under readwrite allow-root failed: " + err.Error(),
		}
	}
	_ = f.Close()
	_ = os.Remove(p)
	return Finding{
		ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
		Status: StatusAvailable, Detail: "allow-root write ok mode=readwrite",
	}
}

func archiveModeLabel(mode ArchiveFSMode) string {
	switch mode {
	case ArchiveFSReadonly:
		return "readonly"
	case ArchiveFSReadWrite:
		return "readwrite"
	default:
		return "none"
	}
}

// NegativeEngineering runs in-child OS denial probes after ApplyEngineering.
func NegativeEngineering(role authority.ProcessRole) []Finding {
	return NegativeEngineeringOpts(role, ApplyOptions{})
}

// NegativeEngineeringOpts includes path allow-list probes for archive roles.
func NegativeEngineeringOpts(role authority.ProcessRole, opts ApplyOptions) []Finding {
	return []Finding{
		NegativeCapMode(), // M3k: FreeBSD cap_getmode; skipped elsewhere
		NegativeFSOpen(),
		NegativeFSRead(),
		NegativeFSPath(role, opts),
		NegativeFSPathWrite(role, opts),
		NegativeExec(),
		NegativePtrace(),
		NegativeRoleNet(role),
	}
}

// FormatNegativeAck appends |NEG-*:status tokens for stub IPC.
func FormatNegativeAck(findings []Finding) string {
	var b strings.Builder
	for _, f := range findings {
		switch f.ID {
		case "NEG-CAP-MODE":
			b.WriteString("|NEG-CAP-MODE:")
		case "NEG-FS-OPEN":
			b.WriteString("|NEG-FS:")
		case "NEG-FS-READ":
			b.WriteString("|NEG-FS-READ:")
		case "NEG-FS-PATH":
			b.WriteString("|NEG-FS-PATH:")
		case "NEG-FS-WRITE":
			b.WriteString("|NEG-FS-WRITE:")
		case "NEG-EXEC":
			b.WriteString("|NEG-EXEC:")
		case "NEG-PTRACE":
			b.WriteString("|NEG-PTRACE:")
		case "NEG-ROLE-NET":
			b.WriteString("|NEG-ROLE-NET:")
		case "NEG-NET-ARCHIVE":
			b.WriteString("|NEG-NET-ARCHIVE:")
		case "NEG-NET-KEYS":
			b.WriteString("|NEG-NET-KEYS:")
		case "NEG-NET-JOURNAL":
			b.WriteString("|NEG-NET-JOURNAL:")
		case "NEG-PARSER-NET":
			b.WriteString("|NEG-PARSER-NET:")
		case "NEG-PARSER-KEYS":
			b.WriteString("|NEG-PARSER-KEYS:")
		case "NEG-PARSER-ARCHIVES":
			b.WriteString("|NEG-PARSER-ARCHIVES:")
		case "NEG-AUTH-ACCEPT":
			b.WriteString("|NEG-AUTH-ACCEPT:")
		case "NEG-AUTH-CONTENTS":
			b.WriteString("|NEG-AUTH-CONTENTS:")
		case "NEG-AUTH-PUB":
			b.WriteString("|NEG-AUTH-PUB:")
		case "NEG-INDEX-PUB":
			b.WriteString("|NEG-INDEX-PUB:")
		case "NEG-INDEX-DELETE":
			b.WriteString("|NEG-INDEX-DELETE:")
		case "NEG-APPLY-KEYS":
			b.WriteString("|NEG-APPLY-KEYS:")
		case "NEG-APPLY-PATH":
			b.WriteString("|NEG-APPLY-PATH:")
		case "NEG-PLAN-WRITE":
			b.WriteString("|NEG-PLAN-WRITE:")
		case "NEG-PLAN-KEYS":
			b.WriteString("|NEG-PLAN-KEYS:")
		case "NEG-PLAN-NET":
			b.WriteString("|NEG-PLAN-NET:")
		case "NEG-AUDIT-DECIDE":
			b.WriteString("|NEG-AUDIT-DECIDE:")
		case "NEG-AUDIT-ARCHIVES":
			b.WriteString("|NEG-AUDIT-ARCHIVES:")
		case "NEG-AUDIT-SECRETS":
			b.WriteString("|NEG-AUDIT-SECRETS:")
		case "NEG-JOURNAL-NET":
			b.WriteString("|NEG-JOURNAL-NET:")
		case "NEG-JOURNAL-POLICY":
			b.WriteString("|NEG-JOURNAL-POLICY:")
		case "NEG-JOURNAL-MUTATE":
			b.WriteString("|NEG-JOURNAL-MUTATE:")
		case "NEG-SUP-PARSER":
			b.WriteString("|NEG-SUP-PARSER:")
		case "NEG-SUP-TRAVERSE":
			b.WriteString("|NEG-SUP-TRAVERSE:")
		case "NEG-SUP-KEYS":
			b.WriteString("|NEG-SUP-KEYS:")
		default:
			continue
		}
		b.WriteString(string(f.Status))
	}
	return b.String()
}
