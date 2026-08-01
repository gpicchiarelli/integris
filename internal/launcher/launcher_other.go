//go:build !unix

package launcher

import "context"

// Handle is unused off Unix.
type Handle struct{}

// Start refuses on non-Unix platforms.
func Start(ctx context.Context, req Request) (*Handle, error) {
	return nil, fail("platform", "launcher requires unix (IP-A-0003)")
}

// Wait refuses on non-Unix platforms.
func (h *Handle) Wait() error {
	return fail("platform", "launcher requires unix (IP-A-0003)")
}

// BuildGoPackage refuses on non-Unix platforms.
func BuildGoPackage(ctx context.Context, moduleRoot, pkg, out string) error {
	return fail("platform", "launcher requires unix (IP-A-0003)")
}
