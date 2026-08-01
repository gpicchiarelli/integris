//go:build darwin && !cgo

package platform

import "fmt"

const aclSupported = false

func aclRoundTrip(path string) error {
	_ = path
	return fmt.Errorf("platform: ACL probe requires cgo (CGO_ENABLED=0 build)")
}

func copyACL(dst, src string) error {
	_, _ = dst, src
	return fmt.Errorf("platform: ACL copy requires cgo (CGO_ENABLED=0 build)")
}

func hasExtendedACL(path string) (bool, error) {
	_ = path
	return false, fmt.Errorf("platform: ACL probe requires cgo (CGO_ENABLED=0 build)")
}
