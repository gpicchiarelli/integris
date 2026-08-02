//go:build linux

package confine

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// NegativeRlimitCore reports whether RLIMIT_CORE soft and hard are zero after
// ApplyEngineering (M5z). Uses getrlimit.
func NegativeRlimitCore() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	zero, err := rlimitCoreZero()
	if err != nil {
		return Finding{
			ID: "NEG-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	if !zero {
		return Finding{
			ID: "NEG-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
			Status: StatusUnexpectedAllow, Detail: "RLIMIT_CORE soft or hard non-zero after apply",
		}
	}
	return Finding{
		ID: "NEG-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
		Status: StatusAvailable, Detail: "getrlimit RLIMIT_CORE soft=hard=0",
	}
}

func rlimitCoreZero() (bool, error) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		return false, err
	}
	return lim.Cur == 0 && lim.Max == 0, nil
}
