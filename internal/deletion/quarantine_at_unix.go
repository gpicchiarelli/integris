//go:build unix

package deletion

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// ExecuteQuarantineMoveAT moves sourceName → quarantine/quarantineName using
// openat/renameat relative to rootFd-equivalent directory fds. Dest must not exist.
func ExecuteQuarantineMoveAT(root string, decision Decision, qp QuarantinePlan) error {
	if !decision.Allowed {
		return stop("decision", "quarantine not allowed: "+decision.Reason)
	}
	if !decision.PermanentDisabled {
		return stop("policy", "permanent deletion path is disabled")
	}
	if err := validateComponent(qp.SourceName); err != nil {
		return err
	}
	if err := validateComponent(qp.QuarantineName); err != nil {
		return err
	}

	rootFd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return stop("io", err.Error())
	}
	defer unix.Close(rootFd)

	// Ensure quarantine directory exists.
	if err := unix.Mkdirat(rootFd, "quarantine", 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return stop("io", err.Error())
	}
	qFd, err := unix.Openat(rootFd, "quarantine", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return stop("io", err.Error())
	}
	defer unix.Close(qFd)

	// Same-volume check via st_dev.
	var rst, qst unix.Stat_t
	if err := unix.Fstat(rootFd, &rst); err != nil {
		return stop("io", err.Error())
	}
	if err := unix.Fstat(qFd, &qst); err != nil {
		return stop("io", err.Error())
	}
	if rst.Dev != qst.Dev {
		return stop("volume", "quarantine directory not same volume")
	}

	from := string(qp.SourceName)
	to := string(qp.QuarantineName)
	if err := renameExclusive(rootFd, qFd, from, to); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return stop("collision", "quarantine object already exists")
		}
		return stop("io", fmt.Sprintf("renameat: %v", err))
	}
	if err := unix.Fsync(qFd); err != nil {
		return stop("io", "fsync quarantine: "+err.Error())
	}
	if err := unix.Fsync(rootFd); err != nil {
		return stop("io", "fsync root: "+err.Error())
	}
	runtime.KeepAlive(qp)
	return nil
}
