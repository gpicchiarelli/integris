//go:build !freebsd

package confine

import "fmt"

func probeAllowRootReadable(opts ApplyOptions) error {
	_ = opts
	return fmt.Errorf("allow-root fd probe is FreeBSD-only")
}

func probeAllowRootCreate(opts ApplyOptions) (func(), error) {
	_ = opts
	return nil, fmt.Errorf("allow-root fd probe is FreeBSD-only")
}
