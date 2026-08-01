//go:build freebsd

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-CAPSICUM", Platform: plat, Control: "cap_enter", Status: StatusUnknown, Detail: "Capsicum entry deferred to platform adapter"},
		{ID: "DISC-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit", Status: StatusUnknown, Detail: "rights limit not applied in engineering process"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available via OpenSocketFabric"},
	}
}
