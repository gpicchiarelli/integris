//go:build linux

package confine

import (
	"bufio"
	"errors"
	"os"
	"runtime"
	"strings"
)

// NegativeCapAmbient reports whether the Linux ambient capability set is empty
// after ApplyEngineering (M5u). Reads CapAmb from /proc/self/status.
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
			Status: StatusUnexpectedAllow, Detail: "CapAmb non-empty after apply",
		}
	}
	return Finding{
		ID: "NEG-CAP-AMBIENT", Platform: plat, Control: "empty_capability_set",
		Status: StatusAvailable, Detail: "CapAmb empty",
	}
}

func ambientCapsEmpty() (bool, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "CapAmb:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "CapAmb:"))
		if v == "" {
			return false, errCapAmbMissing
		}
		for _, c := range v {
			if c != '0' {
				return false, nil
			}
		}
		return true, nil
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	return false, errCapAmbMissing
}

var errCapAmbMissing = errors.New("CapAmb missing from /proc/self/status")
