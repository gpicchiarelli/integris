//go:build unix

package recovery

import (
	"os"
	"syscall"
)

func killSelfAt(label CrashLabel) error {
	if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
		return ioErr(label, err)
	}
	// Unreachable if SIGKILL is delivered; retained for completeness.
	return ioErr(label, errInjectedFault)
}
