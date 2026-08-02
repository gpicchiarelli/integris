//go:build unix

package confine

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// applyRlimitCoreFinding sets RLIMIT_CORE soft=hard=0 and verifies via
// getrlimit (M5z Linux; M6a Darwin/OpenBSD/FreeBSD). Process-wide.
func applyRlimitCoreFinding(plat string) Finding {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return Finding{
			ID: "APPLY-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	zero, err := rlimitCoreZero()
	if err != nil {
		return Finding{
			ID: "APPLY-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
			Status: StatusUnavailable, Detail: "verify: " + err.Error(),
		}
	}
	if !zero {
		return Finding{
			ID: "APPLY-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
			Status: StatusUnavailable, Detail: "RLIMIT_CORE left soft or hard non-zero",
		}
	}
	return Finding{
		ID: "APPLY-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
		Status: StatusAvailable, Detail: "RLIMIT_CORE soft=hard=0; getrlimit verified",
	}
}

func rlimitCoreZero() (bool, error) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		return false, err
	}
	return lim.Cur == 0 && lim.Max == 0, nil
}

// NegativeRlimitCore reports whether RLIMIT_CORE soft and hard are zero after
// ApplyEngineering (M5z/M6a). Uses getrlimit.
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
