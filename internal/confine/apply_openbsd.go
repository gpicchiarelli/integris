//go:build openbsd

package confine

import (
	"runtime"

	"github.com/gpicchiarelli/integris/internal/authority"
	"golang.org/x/sys/unix"
)

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "PROBE-PLEDGE", Platform: plat, Control: "pledge",
		Status: StatusAvailable, Detail: "pledge(2) symbol available",
	}}
}

func applyEngineering(role authority.ProcessRole) []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	var out []Finding
	promises := "stdio unix"
	if RoleMayHoldNetwork(role) {
		promises = "stdio unix inet"
	}
	if err := unix.Pledge(promises, ""); err != nil {
		out = append(out, Finding{
			ID: "APPLY-PLEDGE", Platform: plat, Control: "pledge",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else {
		out = append(out, Finding{
			ID: "APPLY-PLEDGE", Platform: plat, Control: "pledge",
			Status: StatusAvailable, Detail: `promises="` + promises + `"`,
		})
	}
	if err := unix.UnveilBlock(); err != nil {
		out = append(out, Finding{
			ID: "APPLY-UNVEIL", Platform: plat, Control: "unveil",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else {
		out = append(out, Finding{
			ID: "APPLY-UNVEIL", Platform: plat, Control: "unveil",
			Status: StatusAvailable, Detail: "unveil locked with no paths (fd-only)",
		})
	}
	return out
}
