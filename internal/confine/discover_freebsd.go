//go:build freebsd

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-CAPSICUM", Platform: plat, Control: "cap_enter", Status: StatusUnknown, Detail: "applied in child via confine.ApplyEngineering"},
		{ID: "DISC-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit", Status: StatusUnknown, Detail: "LimitConferredFDs applies CAP_READ|WRITE|EVENT before cap_enter"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available via OpenSocketFabric"},
		{ID: "DISC-KEY-FD", Platform: plat, Control: "sealed_mac_key_fd", Status: StatusUnknown, Detail: "launcher.CreateKeyFD uses anon-unlinked FD; FreeBSD memfd seals not wired yet"},
		{ID: "DISC-KQUEUE", Platform: plat, Control: "kqueue_vnode", Status: StatusAvailable, Detail: "platform.VNodeWatch uses kqueue EVFILT_VNODE NOTE_WRITE/DELETE (INT-IC4-0001)"},
	}
}
