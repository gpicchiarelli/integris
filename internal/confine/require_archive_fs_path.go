package confine

import "github.com/gpicchiarelli/integris/internal/authority"

// RequireArchiveFSPathAvailable fails closed when a conferred allow-root cannot
// be opened after apply for archive roles (M5t). Available or Skipped succeed.
// Unavailable refuses — broken allow-roots must not look like a healthy child.
//
// No-op for ArchiveFSNone. Call only after ApplyEngineering in a child.
func RequireArchiveFSPathAvailable(role authority.ProcessRole, opts ApplyOptions) error {
	if RoleArchiveFSMode(role) == ArchiveFSNone {
		return nil
	}
	return RequireArchiveFSPathFinding(NegativeFSPath(role, opts))
}

// RequireArchiveFSPathFinding is the testable core of RequireArchiveFSPathAvailable.
func RequireArchiveFSPathFinding(f Finding) error {
	if f.ID != "NEG-FS-PATH" {
		return &Error{Code: "confine", Message: "expected NEG-FS-PATH finding"}
	}
	switch f.Status {
	case StatusAvailable, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}
