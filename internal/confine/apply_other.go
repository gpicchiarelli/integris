//go:build !linux && !openbsd && !freebsd && !darwin

package confine

import (
	"runtime"

	"github.com/gpicchiarelli/integris/internal/authority"
)

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "PROBE-CONFINEMENT", Platform: plat, Control: "platform",
		Status: StatusSkipped, Detail: "no engineering probe for this OS",
	}}
}

func applyEngineering(role authority.ProcessRole, opts ApplyOptions) []Finding {
	_ = role
	_ = opts
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "APPLY-CONFINEMENT", Platform: plat, Control: "platform",
		Status: StatusSkipped, Detail: "engineering apply deferred for this OS",
	}}
}
