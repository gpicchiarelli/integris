package confine

// RequireSeccompFilter fails closed when Linux SECCOMP_MODE_FILTER is unset
// after apply (M5w). Available or Skipped succeed (Skipped on non-Linux).
// Complements APPLY-SECCOMP (TSYNC install) with a PR_GET_SECCOMP probe.
//
// Call only after ApplyEngineering in a child.
func RequireSeccompFilter() error {
	return RequireSeccompFilterFinding(NegativeSeccompFilter())
}

// RequireSeccompFilterFinding is the testable core of RequireSeccompFilter.
func RequireSeccompFilterFinding(f Finding) error {
	if f.ID != "NEG-SECCOMP" {
		return &Error{Code: "confine", Message: "expected NEG-SECCOMP finding"}
	}
	switch f.Status {
	case StatusAvailable, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}
