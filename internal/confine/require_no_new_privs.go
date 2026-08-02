package confine

// RequireNoNewPrivsSet fails closed when Linux PR_NO_NEW_PRIVS is unset after
// apply (M5v). Available or Skipped succeed (Skipped on non-Linux). Complements
// APPLY-NO-NEW-PRIVS in RequireApplyAvailable with a PR_GET_NO_NEW_PRIVS probe.
//
// Call only after ApplyEngineering in a child.
func RequireNoNewPrivsSet() error {
	return RequireNoNewPrivsFinding(NegativeNoNewPrivs())
}

// RequireNoNewPrivsFinding is the testable core of RequireNoNewPrivsSet.
func RequireNoNewPrivsFinding(f Finding) error {
	if f.ID != "NEG-NO-NEW-PRIVS" {
		return &Error{Code: "confine", Message: "expected NEG-NO-NEW-PRIVS finding"}
	}
	switch f.Status {
	case StatusAvailable, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}
