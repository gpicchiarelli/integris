package confine

// RequireCapAmbientEmpty fails closed when Linux ambient capabilities remain
// after apply (M5u). Available or Skipped succeed (Skipped on non-Linux).
// Complements APPLY-CAP-AMBIENT in RequireApplyAvailable with a CapAmb probe.
//
// Call only after ApplyEngineering in a child. Does not claim empty
// permitted/effective/bounding sets — dedicated-account residual remains.
func RequireCapAmbientEmpty() error {
	return RequireCapAmbientFinding(NegativeCapAmbient())
}

// RequireCapAmbientFinding is the testable core of RequireCapAmbientEmpty.
func RequireCapAmbientFinding(f Finding) error {
	if f.ID != "NEG-CAP-AMBIENT" {
		return &Error{Code: "confine", Message: "expected NEG-CAP-AMBIENT finding"}
	}
	switch f.Status {
	case StatusAvailable, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}
