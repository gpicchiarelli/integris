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

// ApplyEngineering enforces best-effort OS confinement for engineering children
// with an empty path allow-list (deny ambient path opens).
func ApplyEngineering(role authority.ProcessRole) Report {
	return ApplyEngineeringOpts(role, ApplyOptions{})
}

// ApplyEngineeringOpts is ApplyEngineering with optional archive path allow-roots.
// Roots are honored only when RoleArchiveFSMode(role) is non-none; paths are
// EvalSymlinks'd. Call only in child roles.
func ApplyEngineeringOpts(role authority.ProcessRole, opts ApplyOptions) Report {
	r := Report{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	mode := RoleArchiveFSMode(role)
	roots := opts.AllowRoots
	if mode == ArchiveFSNone {
		roots = nil
	} else if len(roots) > 0 {
		norm, err := NormalizeAllowRoots(roots)
		if err != nil {
			r.Findings = append(r.Findings, Finding{
				ID: "APPLY-ALLOW-ROOTS", Platform: runtime.GOOS + "/" + runtime.GOARCH,
				Control: "path_allow_list", Status: StatusUnavailable, Detail: err.Error(),
			})
			sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
			return r
		}
		roots = norm
	}
	r.Findings = append(r.Findings, applyEngineering(role, ApplyOptions{AllowRoots: roots})...)
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
	return r
}
