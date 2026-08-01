//go:build !darwin && !linux && !freebsd && !openbsd

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-UNSUPPORTED", Platform: plat, Control: "platform", Status: StatusUnavailable, Detail: "OS not in declared platform matrix"},
	}
}
