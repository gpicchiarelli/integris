//go:build freebsd

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-CAPSICUM", Platform: plat, Control: "cap_enter", Status: StatusUnknown, Detail: "applied in child via confine.ApplyEngineering"},
		{ID: "DISC-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit", Status: StatusUnknown, Detail: "per-fd rights limit not yet applied"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available via OpenSocketFabric"},
	}
}
