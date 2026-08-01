//go:build darwin

package resource

import "fmt"

// macOS getrlimit(RLIMIT_AS) succeeds but setrlimit returns EINVAL; the limit
// is not enforceable from userland. Callers should treat this as unavailable.
func withSoftAS(soft uint64, fn func() error) error {
	_, _ = soft, fn
	return fmt.Errorf("resource: RLIMIT_AS not enforceable on Darwin")
}
