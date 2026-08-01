//go:build !darwin

package platform

import "fmt"

const aclSupported = false

func aclRoundTrip(path string) error {
	_ = path
	return fmt.Errorf("platform: Darwin extended ACL adapter unavailable on this OS")
}

func copyACL(dst, src string) error {
	_, _ = dst, src
	return fmt.Errorf("platform: Darwin extended ACL adapter unavailable on this OS")
}

func hasExtendedACL(path string) (bool, error) {
	_ = path
	return false, fmt.Errorf("platform: Darwin extended ACL adapter unavailable on this OS")
}
