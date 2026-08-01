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

// WithSoftCPU temporarily lowers the process soft RLIMIT_CPU (seconds) to soft,
// runs fn, then restores the previous limit. Soft is capped to the hard max.
// Unlike WithSoftFSIZE, SIGXCPU disposition is not changed: the default action
// terminates the process. Callers that must observe saturation should
// signal.Notify(SIGXCPU) before invoking fn. This is process CPU-time, not
// system-wide load. On platforms without RLIMIT_CPU, returns an error.
func WithSoftCPU(soft uint64, fn func() error) error {
	return withSoftCPU(soft, fn)
}

// WithSoftNPROC temporarily lowers RLIMIT_NPROC for the duration of fn, then
// restores the previous limit. Soft is capped to the prior hard max.
// Darwin/Linux/OpenBSD lower the soft ceiling; FreeBSD/DragonFly also clamp
// the hard max for the window because soft-only lowering does not reliably
// refuse fork there. Fork/exec under a binding ceiling typically surfaces as
// EAGAIN when the kernel enforces the limit; euid 0 with PRIV_PROC_LIMIT
// (FreeBSD) may still fork. On Darwin, lowering NPROC soft may permanently
// clamp the hard max to the prior soft value (Cur is still restored). On
// platforms without RLIMIT_NPROC, returns an error.
func WithSoftNPROC(soft uint64, fn func() error) error {
	return withSoftNPROC(soft, fn)
// WithSoftAS temporarily lowers the process address/data-space soft ceiling
// for the duration of fn, then restores the previous limit. Soft is capped to
// the hard max. Linux/FreeBSD/NetBSD use RLIMIT_AS; OpenBSD uses RLIMIT_DATA
// (covers anonymous mmap). Oversized anonymous mmap under a binding ceiling
// typically surfaces as ENOMEM. Darwin reports RLIMIT_AS via getrlimit but
// setrlimit returns EINVAL (not enforceable); WithSoftAS errors there. On
// platforms without a suitable limit, returns an error.
func WithSoftAS(soft uint64, fn func() error) error {
	return withSoftAS(soft, fn)
}
