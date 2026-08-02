//go:build linux

package confine

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// NegativeDumpable reports whether PR_DUMPABLE is cleared after
// ApplyEngineering (M5x). Uses PR_GET_DUMPABLE.
func NegativeDumpable() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	clear, err := dumpableClear()
	if err != nil {
		return Finding{
			ID: "NEG-DUMPABLE", Platform: plat, Control: "dumpable",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	if !clear {
		return Finding{
			ID: "NEG-DUMPABLE", Platform: plat, Control: "dumpable",
			Status: StatusUnexpectedAllow, Detail: "PR_DUMPABLE set after apply",
		}
	}
	return Finding{
		ID: "NEG-DUMPABLE", Platform: plat, Control: "dumpable",
		Status: StatusAvailable, Detail: "PR_GET_DUMPABLE cleared",
	}
}

func dumpableClear() (bool, error) {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return false, err
	}
	return v == 0, nil
}
