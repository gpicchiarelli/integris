package confine

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
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
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Finding{
			ID: "NEG-FS-OPEN", Platform: plat, Control: "filesystem_writes",
			Status: StatusUnavailable, Detail: "probe nonce: " + err.Error(),
		}
	}
	p := filepath.Join(dir, "integris-neg-fs-"+hex.EncodeToString(nonce[:]))
	if runtime.GOOS == "openbsd" {
		// O_CREATE without wpath aborts under pledge; probe unveil deny via open.
		_, err := os.Open(p)
		if err == nil {
			_ = os.Remove(p) // unreachable if path was unique and non-existent
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
	// Stale fixed-name collisions must not look like confinement deny (M5p).
	if errors.Is(err, os.ErrExist) {
		return Finding{
			ID: "NEG-FS-OPEN", Platform: plat, Control: "filesystem_writes",
			Status: StatusUnavailable, Detail: "probe path exists: " + p,
		}
	}
	return Finding{
		ID: "NEG-FS-OPEN", Platform: plat, Control: "filesystem_writes",
		Status: StatusDeniedExpected, Detail: err.Error(),
	}
}

// AmbientFSReadProbePath is the well-known path used by NEG-FS-READ.
const AmbientFSReadProbePath = "/etc/hosts"

// AmbientFSReadProbeExisted reports whether AmbientFSReadProbePath exists.
// Call before ApplyEngineering: after locked unveil, Landlock, CapEnter, or
// Seatbelt, absence and deny are not always distinguishable (OpenBSD unveil(2)
// may return ENOENT for non-unveiled paths).
func AmbientFSReadProbeExisted() bool {
	_, err := os.Stat(AmbientFSReadProbePath)
	return err == nil
}

// NegativeFSRead attempts a path-based open of AmbientFSReadProbePath after
// apply. Landlock empty ruleset, locked unveil, Capsicum, and Darwin Seatbelt
// (no ambient file-read-data) should deny it; conferred FDs remain readable.
//
// probeExisted must be the result of AmbientFSReadProbeExisted before apply
// (M5r). When false, returns Unavailable so hosts-less environments cannot
// false-pass RequireAmbientFSReadDenied (M5q). When true, any open failure —
// including OpenBSD unveil ENOENT — is DeniedExpected.
func NegativeFSRead(probeExisted bool) Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	switch runtime.GOOS {
	case "linux", "openbsd", "freebsd", "darwin":
	default:
		return Finding{
			ID: "NEG-FS-READ", Platform: plat, Control: "filesystem_reads",
			Status: StatusSkipped, Detail: "no engineering path-read denylist on this OS",
		}
	}
	if !probeExisted {
		return Finding{
			ID: "NEG-FS-READ", Platform: plat, Control: "filesystem_reads",
			Status: StatusUnavailable, Detail: "probe path missing: " + AmbientFSReadProbePath,
		}
	}
	f, err := os.Open(AmbientFSReadProbePath)
	if err == nil {
		_ = f.Close()
		return Finding{
			ID: "NEG-FS-READ", Platform: plat, Control: "filesystem_reads",
			Status: StatusUnexpectedAllow, Detail: "path open " + AmbientFSReadProbePath + " succeeded after apply",
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
	probe, err := probeAllowRootPath(roots)
	if err != nil {
		return Finding{
			ID: "NEG-FS-PATH", Platform: plat, Control: "path_allow_list",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	f, err := os.Open(probe)
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

// probeAllowRootPath returns a path safe to open after ApplyEngineering.
// On OpenBSD, locked unveil can deny EvalSymlinks walks, so absolute roots
// are cleaned without a second symlink resolution.
func probeAllowRootPath(roots []string) (string, error) {
	if len(roots) == 0 {
		return "", errors.New("normalize failed")
	}
	if runtime.GOOS == "openbsd" && filepath.IsAbs(roots[0]) {
		return filepath.Clean(roots[0]), nil
	}
	norm, err := NormalizeAllowRoots(roots)
	if err != nil {
		return "", err
	}
	if len(norm) == 0 {
		return "", errors.New("normalize failed")
	}
	return norm[0], nil
}

// NegativeFSPathWrite attempts create/write under a conferred allow-root.
// ArchiveFSReadonly roles must be denied; ArchiveFSReadWrite must succeed.
// On FreeBSD, uses openat on a conferred directory FD.
// Probe paths use a unique nonce name; EEXIST is Unavailable, not deny (M5s).
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
			// EEXIST is infrastructure collision, not Capsicum deny (M5s).
			if errors.Is(err, os.ErrExist) {
				return Finding{
					ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
					Status: StatusUnavailable, Detail: "probe path exists under allow-root fd",
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
	probe, err := probeAllowRootPath(roots)
	if err != nil {
		return Finding{
			ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Finding{
			ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
			Status: StatusUnavailable, Detail: "probe nonce: " + err.Error(),
		}
	}
	p := filepath.Join(probe, "integris-neg-fs-"+hex.EncodeToString(nonce[:]))
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
		// Stale fixed-name collisions must not look like confinement deny (M5s;
		// twin of NEG-FS-OPEN EEXIST honesty in M5p). Unique nonce makes this
		// rare; still refuse to treat EEXIST as DeniedExpected.
		if errors.Is(err, os.ErrExist) {
			return Finding{
				ID: "NEG-FS-WRITE", Platform: plat, Control: "path_allow_list_write",
				Status: StatusUnavailable, Detail: "probe path exists: " + p,
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
// fsReadProbeExisted must be AmbientFSReadProbeExisted before apply (M5r).
func NegativeEngineering(role authority.ProcessRole, fsReadProbeExisted bool) []Finding {
	return NegativeEngineeringOpts(role, ApplyOptions{}, fsReadProbeExisted)
}

// NegativeEngineeringOpts includes path allow-list probes for archive roles.
// fsReadProbeExisted must be AmbientFSReadProbeExisted before apply (M5r).
func NegativeEngineeringOpts(role authority.ProcessRole, opts ApplyOptions, fsReadProbeExisted bool) []Finding {
	return []Finding{
		NegativeCapMode(),       // M3k: FreeBSD cap_getmode; skipped elsewhere
		NegativeCapAmbient(),    // M5u: Linux CapAmb empty; skipped elsewhere
		NegativeNoNewPrivs(),    // M5v: Linux PR_NO_NEW_PRIVS; skipped elsewhere
		NegativeSeccompFilter(), // M5w: Linux SECCOMP_MODE_FILTER; skipped elsewhere
		NegativeFSOpen(),
		NegativeFSRead(fsReadProbeExisted),
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
		case "NEG-CAP-AMBIENT":
			b.WriteString("|NEG-CAP-AMBIENT:")
		case "NEG-NO-NEW-PRIVS":
			b.WriteString("|NEG-NO-NEW-PRIVS:")
		case "NEG-SECCOMP":
			b.WriteString("|NEG-SECCOMP:")
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
