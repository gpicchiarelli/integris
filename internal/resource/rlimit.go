package resource

// WithSoftNOFILE temporarily lowers the process soft RLIMIT_NOFILE to soft,
// runs fn, then restores the previous limit. Soft is capped to the hard max.
// On platforms without RLIMIT_NOFILE, WithSoftNOFILE returns an error.
func WithSoftNOFILE(soft uint64, fn func() error) error {
	return withSoftNOFILE(soft, fn)
}
