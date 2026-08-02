package confine

// RequireDumpableClear fails closed when Linux PR_DUMPABLE is set after
// apply (M5x). Available or Skipped succeed (Skipped on non-Linux). Complements
// APPLY-DUMPABLE in RequireApplyAvailable with a PR_GET_DUMPABLE probe.
//
// Call only after ApplyEngineering in a child.
func RequireDumpableClear() error {
	return RequireDumpableFinding(NegativeDumpable())
}

// RequireDumpableFinding is the testable core of RequireDumpableClear.
func RequireDumpableFinding(f Finding) error {
	if f.ID != "NEG-DUMPABLE" {
		return &Error{Code: "confine", Message: "expected NEG-DUMPABLE finding"}
	}
	switch f.Status {
	case StatusAvailable, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}
