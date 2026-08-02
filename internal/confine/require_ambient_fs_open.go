package confine

// RequireAmbientFSOpenDenied fails closed when ambient path create/open outside
// allow-roots remains allowed after apply (M5p). DeniedExpected or Skipped
// succeed. Complements RequireAmbientFSReadDenied (M3q): reads vs writes.
//
// Call only after ApplyEngineering in a child. On OpenBSD, NegativeFSOpen
// probes unveil via open (not O_CREATE) to avoid pledge SIGABRT without wpath.
func RequireAmbientFSOpenDenied() error {
	return RequireAmbientFSOpenFinding(NegativeFSOpen())
}
