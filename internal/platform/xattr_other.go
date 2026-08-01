//go:build !unix

package platform

func copyXattr(dst, src string) error {
	_, _ = dst, src
	return nil
}
