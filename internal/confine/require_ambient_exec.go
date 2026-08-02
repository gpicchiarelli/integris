package confine

// RequireAmbientExecDenied fails closed when ambient process exec remains
// allowed after apply (M5o). DeniedExpected or Skipped succeed (Skipped covers
// OS without an engineering exec denylist). Unlike RequireAmbientRoleNetDenied,
// FreeBSD is not skipped: CapEnter denies unix.Exec.
//
// Call only after ApplyEngineering in a child. NegativeExec on OpenBSD is a
// soft DeniedExpected (in-process exec would SIGABRT under pledge).
func RequireAmbientExecDenied() error {
	return RequireAmbientExecFinding(NegativeExec())
}
