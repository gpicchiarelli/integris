//go:build !darwin

package platform

import "fmt"

const aclSupported = false

func aclRoundTrip(path string) error {
	_ = path
	return fmt.Errorf("platform: Darwin extended ACL adapter unavailable on this OS")
}
