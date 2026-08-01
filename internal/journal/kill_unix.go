//go:build unix

package journal

import (
	"os"
	"syscall"
)

func killSelfAt(label string) error {
	if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
		return err
	}
	// Unreachable if SIGKILL is delivered; retained for completeness.
	return injectedCrash{label}
}
