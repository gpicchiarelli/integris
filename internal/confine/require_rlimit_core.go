package confine

// RequireRlimitCoreZero fails closed when Unix RLIMIT_CORE soft or hard is
// non-zero after apply (M5z Linux; M6a Darwin/OpenBSD/FreeBSD). Available or
// Skipped succeed (Skipped on non-Unix). Complements APPLY-RLIMIT-CORE in
// RequireApplyAvailable with a getrlimit probe.
//
// Call only after ApplyEngineering in a child.
func RequireRlimitCoreZero() error {
	return RequireRlimitCoreFinding(NegativeRlimitCore())
}

// RequireRlimitCoreFinding is the testable core of RequireRlimitCoreZero.
func RequireRlimitCoreFinding(f Finding) error {
	if f.ID != "NEG-RLIMIT-CORE" {
		return &Error{Code: "confine", Message: "expected NEG-RLIMIT-CORE finding"}
	}
	switch f.Status {
	case StatusAvailable, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}
