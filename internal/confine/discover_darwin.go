//go:build darwin

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-HARDENED-RUNTIME", Platform: plat, Control: "hardened_runtime", Status: StatusUnknown, Detail: "requires signed binary inspection"},
		{ID: "DISC-SANDBOX", Platform: plat, Control: "app_sandbox", Status: StatusUnknown, Detail: "deployment-dependent; not claimed equivalent to capability mode"},
		{ID: "DISC-LAUNCHD-IDENTITY", Platform: plat, Control: "dedicated_identity", Status: StatusUnavailable, Detail: "no launchd child identities until spawn adapter"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available in-process via OpenSocketFabric"},
		{ID: "DISC-KEY-FD", Platform: plat, Control: "sealed_mac_key_fd", Status: StatusUnknown, Detail: "launcher.CreateKeyFD uses anon-unlinked FD; memfd seals unavailable on Darwin"},
	}
}
