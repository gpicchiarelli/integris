package confine

import (
	"runtime"
	"sort"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// ProbeEngineering reports confinement knobs without enforcing Landlock/pledge
// restrictions that would affect the calling process permanently.
func ProbeEngineering() Report {
	r := Report{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	r.Findings = append(r.Findings, probeEngineering()...)
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
	return r
}

// ApplyEngineering enforces best-effort OS confinement for engineering children.
// Role parameterizes network policy: CapNetworkSockets holders keep ambient
// network; all other roles get OS denials where the platform can enforce them.
// On Linux this sets no_new_privs and a Landlock domain that denies new FS opens
// (pre-opened fds remain usable). On OpenBSD it pledges and locks unveil.
// Unsupported platforms return StatusSkipped. Call only in child roles.
func ApplyEngineering(role authority.ProcessRole) Report {
	r := Report{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	r.Findings = append(r.Findings, applyEngineering(role)...)
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
	return r
}
