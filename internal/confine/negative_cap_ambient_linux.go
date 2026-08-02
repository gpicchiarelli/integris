//go:build linux

package confine

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// NegativeCapAmbient reports whether the Linux ambient capability set is empty
// after ApplyEngineering (M5u). Uses PR_CAP_AMBIENT_IS_SET so Landlock cannot
// deny the probe by blocking /proc/self/status.
func NegativeCapAmbient() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	empty, err := ambientCapsEmpty()
	if err != nil {
		return Finding{
			ID: "NEG-CAP-AMBIENT", Platform: plat, Control: "empty_capability_set",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	if !empty {
		return Finding{
			ID: "NEG-CAP-AMBIENT", Platform: plat, Control: "empty_capability_set",
			Status: StatusUnexpectedAllow, Detail: "ambient capability remains set",
		}
	}
	return Finding{
		ID: "NEG-CAP-AMBIENT", Platform: plat, Control: "empty_capability_set",
		Status: StatusAvailable, Detail: "ambient capability set empty",
	}
}

// ambientCapsEmpty reports whether no ambient capabilities remain, via
// PR_CAP_AMBIENT_IS_SET (works after Landlock; does not need /proc).
func ambientCapsEmpty() (bool, error) {
	for cap := uintptr(0); cap < 64; cap++ {
		r1, _, errno := unix.Syscall6(
			unix.SYS_PRCTL,
			uintptr(unix.PR_CAP_AMBIENT),
			uintptr(unix.PR_CAP_AMBIENT_IS_SET),
			cap, 0, 0, 0,
		)
		if errno == unix.EINVAL {
			// Past CAP_LAST_CAP.
			break
		}
		if errno != 0 {
			return false, errno
		}
		if r1 != 0 {
			return false, nil
		}
	}
	return true, nil
}
