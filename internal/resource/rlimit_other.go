//go:build !unix

package resource

import "fmt"

func withSoftNOFILE(soft uint64, fn func() error) error {
	_, _ = soft, fn
	return fmt.Errorf("resource: RLIMIT_NOFILE unavailable on this OS")
}

func withSoftFSIZE(soft uint64, fn func() error) error {
	_, _ = soft, fn
	return fmt.Errorf("resource: RLIMIT_FSIZE unavailable on this OS")
}

func withSoftCPU(soft uint64, fn func() error) error {
	_, _ = soft, fn
	return fmt.Errorf("resource: RLIMIT_CPU unavailable on this OS")
}

func withSoftAS(soft uint64, fn func() error) error {
	_, _ = soft, fn
	return fmt.Errorf("resource: RLIMIT_AS unavailable on this OS")
}
