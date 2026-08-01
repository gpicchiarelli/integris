//go:build openbsd

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-PLEDGE", Platform: plat, Control: "pledge", Status: StatusUnknown, Detail: "pledge not applied in engineering process"},
		{ID: "DISC-UNVEIL", Platform: plat, Control: "unveil", Status: StatusUnknown, Detail: "unveil not applied in engineering process"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available via OpenSocketFabric"},
		{ID: "DISC-KEY-FD", Platform: plat, Control: "sealed_mac_key_fd", Status: StatusUnknown, Detail: "launcher.CreateKeyFD uses anon-unlinked FD; no memfd on OpenBSD"},
	}
}
