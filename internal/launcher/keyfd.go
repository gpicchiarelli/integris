package launcher

// KeyTransport names how the MAC key FD was created (IP-A-0003).
type KeyTransport string

const (
	// KeyTransportMemfd is a Linux memfd with write/shrink/grow seals.
	KeyTransportMemfd KeyTransport = "memfd-sealed"
	// KeyTransportAnonFile is an unlinked temp file reopened O_RDONLY
	// (Darwin/FreeBSD/OpenBSD engineering path until memfd/SCM lands).
	KeyTransportAnonFile KeyTransport = "anon-unlinked"
)
