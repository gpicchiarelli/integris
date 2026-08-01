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
		{ID: "DISC-SENDFILE", Platform: plat, Control: "sendfile", Status: StatusUnavailable, Detail: "x/sys unix.Sendfile returns ENOSYS on OpenBSD; no platform.SendFile path"},
		{ID: "DISC-KQUEUE", Platform: plat, Control: "kqueue_vnode", Status: StatusAvailable, Detail: "platform.VNodeWatch uses kqueue EVFILT_VNODE NOTE_WRITE/DELETE (INT-IC4-0001)"},
	}
}
