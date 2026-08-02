package launcher

// KeyTransport names how the MAC key FD was created/conferred (IP-A-0003).
type KeyTransport string

const (
	// KeyTransportMemfd is a sealed anonymous FD (Linux memfd_create;
	// FreeBSD shm_open2+F_ADD_SEALS) with write/shrink/grow seals.
	KeyTransportMemfd KeyTransport = "memfd-sealed"
	// KeyTransportAnonFile is an unlinked temp file reopened O_RDONLY
	// (Darwin/OpenBSD engineering path until memfd seals land).
	KeyTransportAnonFile KeyTransport = "anon-unlinked"
	// KeyTransportSCMRights is the default conferral: key FD via SCM_RIGHTS after
	// spawn (ExtraFiles carries only the IPC socket). Underlying FD may still be
	// memfd-sealed or anon-unlinked.
	KeyTransportSCMRights KeyTransport = "scm-rights"
)
