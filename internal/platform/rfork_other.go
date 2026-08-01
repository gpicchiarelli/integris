//go:build !darwin

package platform

func copyResourceFork(dst, src string) error {
	_, _ = dst, src
	return nil
}
