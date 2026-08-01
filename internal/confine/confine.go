// Package confine records platform confinement discovery and negative-probe
// scaffolding per docs/platform-matrix.md.
//
// Results are observational. An unconfined developer process will often report
// unexpected_allow; that is not release evidence. OS spawn remains out of
// scope (Go profile prohibits os/exec in product code).
package confine

import (
	"runtime"
	"sort"
)

// Status classifies a probe outcome.
type Status string

const (
	StatusAvailable         Status = "available"
	StatusUnavailable       Status = "unavailable"
	StatusUnknown           Status = "unknown"
	StatusDeniedExpected    Status = "denied_as_expected"
	StatusUnexpectedAllow   Status = "unexpected_allow"
	StatusSkipped           Status = "skipped"
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

// NegativeBaseline returns role-oriented negative probes that an *unconfined*
// process is expected to fail-open on (unexpected_allow or skipped). Used to
// document the gap until OS-enforced children exist.
func NegativeBaseline() Report {
	r := Report{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	probes := []struct {
		id, control, detail string
	}{
		{"NEG-NET-ARCHIVE", "archive_descriptors", "net role must not open archive roots"},
		{"NEG-PARSER-NET", "network_sockets", "parser role must not create sockets"},
		{"NEG-PLAN-WRITE", "filesystem_writes", "plan role must not mutate archives"},
		{"NEG-AUDIT-DECIDE", "operation_decisions", "audit role must not authorize"},
		{"NEG-JOURNAL-NET", "network", "journal role must not hold network"},
	}
	for _, p := range probes {
		r.Findings = append(r.Findings, Finding{
			ID: p.id, Platform: runtime.GOOS + "/" + runtime.GOARCH,
			Control: p.control, Status: StatusSkipped,
			Detail: p.detail + "; skipped until confined child spawn exists",
		})
	}
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
	return r
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
