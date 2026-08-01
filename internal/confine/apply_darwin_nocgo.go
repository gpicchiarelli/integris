//go:build darwin && !cgo

package confine

import (
	"runtime"

	"github.com/gpicchiarelli/integris/internal/authority"
)

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "PROBE-SEATBELT", Platform: plat, Control: "seatbelt",
		Status: StatusSkipped, Detail: "sandbox_init requires cgo (CGO_ENABLED=0 build)",
	}}
}

func applyEngineering(role authority.ProcessRole, opts ApplyOptions) []Finding {
	_ = role
	_ = opts
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "APPLY-SEATBELT", Platform: plat, Control: "seatbelt",
		Status: StatusSkipped, Detail: "sandbox_init requires cgo (CGO_ENABLED=0 build)",
	}}
}
