// Package confine records platform confinement discovery and negative-probe
// scaffolding per docs/platform-matrix.md.
//
// Results are observational. An unconfined developer process will often report
// unexpected_allow; that is not release evidence. Product kernels must not
// import os/exec; in-child NEG-EXEC uses unix.Exec only inside confined stubs.
package confine

import (
	"runtime"
	"sort"
)

// Status classifies a probe outcome.
type Status string

const (
	StatusAvailable       Status = "available"
	StatusUnavailable     Status = "unavailable"
	StatusUnknown         Status = "unknown"
	StatusDeniedExpected  Status = "denied_as_expected"
	StatusUnexpectedAllow Status = "unexpected_allow"
	StatusSkipped         Status = "skipped"
)

// Finding is one discovery or negative-probe row.
type Finding struct {
	ID       string `json:"id"`
	Platform string `json:"platform"`
	Control  string `json:"control"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
}

// Report is a stable-sorted confinement observation set.
type Report struct {
	GOOS     string    `json:"goos"`
	GOARCH   string    `json:"goarch"`
	Findings []Finding `json:"findings"`
}

// Discover runs platform-specific capability discovery (best-effort).
func Discover() Report {
	r := Report{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	r.Findings = append(r.Findings, discoverPlatform()...)
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
	return r
}

// NegativeBaseline is retained for callers that expect a Report shape. All
// role-semantic IDs are implemented by NegativeRoleSemantic; this returns an
// empty finding set (no deferred stubs).
func NegativeBaseline() Report {
	return Report{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}

// RequireApplyAvailable fails closed when any APPLY-* control did not apply.
// Used by M2k release-shaped launch (Unavailable or Skipped both refuse).
func (r Report) RequireApplyAvailable() error {
	var sawApply bool
	for _, f := range r.Findings {
		if len(f.ID) < 6 || f.ID[:6] != "APPLY-" {
			continue
		}
		sawApply = true
		switch f.Status {
		case StatusUnavailable, StatusSkipped:
			return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
		}
	}
	if !sawApply {
		return &Error{Code: "confine", Message: "no APPLY-* findings"}
	}
	return nil
}

// RequireCapModeAvailable fails closed when FreeBSD capability mode is not
// confirmed after apply (M3m). Skipped on non-FreeBSD (cap_getmode absent).
func RequireCapModeAvailable() error {
	return RequireCapModeFinding(NegativeCapMode())
}

// RequireCapModeFinding is the testable core of RequireCapModeAvailable.
func RequireCapModeFinding(f Finding) error {
	if f.ID != "NEG-CAP-MODE" {
		return &Error{Code: "confine", Message: "expected NEG-CAP-MODE finding"}
	}
	switch f.Status {
	case StatusAvailable, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}

// RequireAllowRootLimitFinding fails closed when FreeBSD allow-root
// cap_rights_limit did not apply (M3n). Available or Skipped (no FDs /
// non-FreeBSD) succeed; Unavailable and other statuses refuse.
func RequireAllowRootLimitFinding(f Finding) error {
	if f.ID != "APPLY-CAP-ALLOW-ROOTS" {
		return &Error{Code: "confine", Message: "expected APPLY-CAP-ALLOW-ROOTS finding"}
	}
	switch f.Status {
	case StatusAvailable, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}

// RequireConferredLimitFinding fails closed when FreeBSD conferred IPC/key
// cap_rights_limit did not apply (M3o). Available or Skipped (non-FreeBSD)
// succeed; Unavailable and other statuses refuse.
func RequireConferredLimitFinding(f Finding) error {
	if f.ID != "APPLY-CAP-RIGHTS" {
		return &Error{Code: "confine", Message: "expected APPLY-CAP-RIGHTS finding"}
	}
	switch f.Status {
	case StatusAvailable, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}

// RequireAmbientFSReadDenied fails closed when ambient path open is still
// allowed after apply (M3q). DeniedExpected or Skipped succeed.
func RequireAmbientFSReadDenied() error {
	return RequireAmbientFSReadFinding(NegativeFSRead())
}

// RequireAmbientFSReadFinding is the testable core of RequireAmbientFSReadDenied.
func RequireAmbientFSReadFinding(f Finding) error {
	if f.ID != "NEG-FS-READ" {
		return &Error{Code: "confine", Message: "expected NEG-FS-READ finding"}
	}
	switch f.Status {
	case StatusDeniedExpected, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}

// RequireAmbientRoleNetFinding is retained for a future FreeBSD ambient-socket
// deny that is compatible with allow-root CapRightsLimit (M3s residual:
// CapEnter alone does not deny AF_INET; jail ip-disable conflicts with
// conferred directory FD rights-limit). DeniedExpected or Skipped succeed.
func RequireAmbientRoleNetFinding(f Finding) error {
	if f.ID != "NEG-ROLE-NET" {
		return &Error{Code: "confine", Message: "expected NEG-ROLE-NET finding"}
	}
	switch f.Status {
	case StatusDeniedExpected, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}

// HasUnexpectedAllow reports whether any finding is unexpected_allow.
func (r Report) HasUnexpectedAllow() bool {
	for _, f := range r.Findings {
		if f.Status == StatusUnexpectedAllow {
			return true
		}
	}
	return false
}
