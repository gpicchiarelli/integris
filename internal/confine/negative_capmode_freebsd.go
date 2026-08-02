//go:build freebsd

package confine

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// NegativeCapMode reports whether the process is in Capsicum capability mode (M3k).
func NegativeCapMode() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	mode, err := capGetMode()
	if err != nil {
		return Finding{
			ID: "NEG-CAP-MODE", Platform: plat, Control: "cap_getmode",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	if mode != 0 {
		return Finding{
			ID: "NEG-CAP-MODE", Platform: plat, Control: "cap_getmode",
			Status: StatusAvailable, Detail: "capability mode entered",
		}
	}
	return Finding{
		ID: "NEG-CAP-MODE", Platform: plat, Control: "cap_getmode",
		Status: StatusUnexpectedAllow, Detail: "not in capability mode after apply",
	}
}

func capGetMode() (uint32, error) {
	var mode uint32
	// CapGetMode is not wrapped in x/sys; syscall needs the out-pointer.
	_, _, errno := unix.Syscall(unix.SYS_CAP_GETMODE, uintptr(unsafe.Pointer(&mode)), 0, 0) // nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
	if errno != 0 {
		return 0, errno
	}
	return mode, nil
}
