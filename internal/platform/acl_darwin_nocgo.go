//go:build darwin && !cgo

package platform

import "fmt"

const aclSupported = false

func aclRoundTrip(path string) error {
	_ = path
	return fmt.Errorf("platform: ACL probe requires cgo (CGO_ENABLED=0 build)")
}
