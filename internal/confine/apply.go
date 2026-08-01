package confine

import (
	"runtime"
	"sort"
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
// On Linux this sets no_new_privs and a Landlock domain that denies new FS opens
// (pre-opened fds remain usable). On OpenBSD it pledges stdio+unix and locks
// unveil. Unsupported platforms return StatusSkipped. Call only in child roles.
func ApplyEngineering() Report {
	r := Report{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	r.Findings = append(r.Findings, applyEngineering()...)
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
	return r
}
