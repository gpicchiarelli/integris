//go:build !(darwin || freebsd || openbsd)

package platform

func copyBSDFlags(dst, src string) error {
	_, _ = dst, src
	return nil
}
