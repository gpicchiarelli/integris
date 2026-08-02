package confine

// RequireTraceCtlDisabled fails closed when FreeBSD PROC_TRACE_STATUS is not
// -1 after apply (M6c). Available or Skipped succeed (Skipped on non-FreeBSD).
// Complements APPLY-TRACE-CTL in RequireApplyAvailable with a STATUS probe.
//
// Call only after ApplyEngineering in a child.
func RequireTraceCtlDisabled() error {
	return RequireTraceCtlFinding(NegativeTraceCtl())
}

// RequireTraceCtlFinding is the testable core of RequireTraceCtlDisabled.
func RequireTraceCtlFinding(f Finding) error {
	if f.ID != "NEG-TRACE-CTL" {
		return &Error{Code: "confine", Message: "expected NEG-TRACE-CTL finding"}
	}
	switch f.Status {
	case StatusAvailable, StatusSkipped:
		return nil
	default:
		return &Error{Code: "confine", Message: f.ID + ": " + string(f.Status) + ": " + f.Detail}
	}
}
