//go:build !linux && !openbsd

package confine

import "runtime"

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "PROBE-CONFINEMENT", Platform: plat, Control: "platform",
		Status: StatusSkipped, Detail: "no engineering probe for this OS",
	}}
}

func applyEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "APPLY-CONFINEMENT", Platform: plat, Control: "platform",
		Status: StatusSkipped, Detail: "engineering apply deferred for this OS",
	}}
}
