package resource

// WithSoftNOFILE temporarily lowers the process soft RLIMIT_NOFILE to soft,
// runs fn, then restores the previous limit. Soft is capped to the hard max.
// On platforms without RLIMIT_NOFILE, WithSoftNOFILE returns an error.
func WithSoftNOFILE(soft uint64, fn func() error) error {
	return withSoftNOFILE(soft, fn)
}

// WithSoftFSIZE temporarily lowers the process soft RLIMIT_FSIZE to soft,
// runs fn, then restores the previous limit. Soft is capped to the hard max.
// SIGXFSZ is ignored for the duration of fn so writes surface as EFBIG instead
// of terminating the process. On platforms without RLIMIT_FSIZE, returns an error.
func WithSoftFSIZE(soft uint64, fn func() error) error {
	return withSoftFSIZE(soft, fn)
}
