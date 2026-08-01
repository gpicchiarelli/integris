//go:build freebsd

package confine

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "PROBE-CAPSICUM", Platform: plat, Control: "cap_enter",
		Status: StatusAvailable, Detail: "cap_enter(2) available",
	}}
}

func applyEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	if err := unix.CapEnter(); err != nil {
		return []Finding{{
			ID: "APPLY-CAPSICUM", Platform: plat, Control: "cap_enter",
			Status: StatusUnavailable, Detail: err.Error(),
		}}
	}
	return []Finding{{
		ID: "APPLY-CAPSICUM", Platform: plat, Control: "cap_enter",
		Status: StatusAvailable, Detail: "capability mode entered (fd-only)",
	}}
}
