package confine

import "github.com/gpicchiarelli/integris/internal/authority"

// RequireArchiveFSWriteDenied fails closed when create under a conferred
// allow-root remains allowed for ArchiveFSReadonly roles after apply (M5s).
// DeniedExpected or Skipped succeed. Unavailable (e.g. EEXIST probe collision)
// refuses — infrastructure failure must not look like confinement deny.
//
// No-op for ArchiveFSNone / ArchiveFSReadWrite (negative probe is Skipped or
// asserts success). Call only after ApplyEngineering in a child.
func RequireArchiveFSWriteDenied(role authority.ProcessRole, opts ApplyOptions) error {
	if RoleArchiveFSMode(role) != ArchiveFSReadonly {
		return nil
	}
	return RequireArchiveFSWriteFinding(NegativeFSPathWrite(role, opts))
}

// RequireArchiveFSWriteFinding is the testable core of RequireArchiveFSWriteDenied.
func RequireArchiveFSWriteFinding(f Finding) error {
	if f.ID != "NEG-FS-WRITE" {
		return &Error{Code: "confine", Message: "expected NEG-FS-WRITE finding"}
	}
	switch f.Status {
	case StatusDeniedExpected, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}
