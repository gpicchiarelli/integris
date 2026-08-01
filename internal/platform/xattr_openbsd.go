//go:build openbsd

package platform

// OpenBSD has no Setxattr/Listxattr/Getxattr in golang.org/x/sys/unix.
// CopyXattr is a successful no-op; CapXattr probes report unrepresentable.
func copyXattr(dst, src string) error {
	_, _ = dst, src
	return nil
}
