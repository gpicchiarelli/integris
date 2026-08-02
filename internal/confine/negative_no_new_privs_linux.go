//go:build linux

package confine

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// NegativeNoNewPrivs reports whether PR_NO_NEW_PRIVS is set after
// ApplyEngineering (M5v). Uses PR_GET_NO_NEW_PRIVS.
func NegativeNoNewPrivs() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	set, err := noNewPrivsSet()
	if err != nil {
		return Finding{
			ID: "NEG-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	if !set {
		return Finding{
			ID: "NEG-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs",
			Status: StatusUnexpectedAllow, Detail: "PR_NO_NEW_PRIVS unset after apply",
		}
	}
	return Finding{
		ID: "NEG-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs",
		Status: StatusAvailable, Detail: "PR_GET_NO_NEW_PRIVS set",
	}
}

func noNewPrivsSet() (bool, error) {
	v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return false, err
	}
	return v != 0, nil
}
