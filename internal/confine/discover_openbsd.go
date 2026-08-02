//go:build openbsd

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-PLEDGE", Platform: plat, Control: "pledge", Status: StatusAvailable, Detail: "engineering ApplyEngineering uses role-parameterized pledge(2)"},
		{ID: "DISC-UNVEIL", Platform: plat, Control: "unveil", Status: StatusAvailable, Detail: "engineering ApplyEngineering unveils AllowRoots then UnveilBlock before pledge"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available via OpenSocketFabric"},
		{ID: "DISC-KEY-FD", Platform: plat, Control: "sealed_mac_key_fd", Status: StatusUnavailable, Detail: "M4c residual: launcher.CreateKeyFD uses anon-unlinked O_RDONLY FD; OpenBSD has no memfd/F_ADD_SEALS"},
		{ID: "DISC-SENDFILE", Platform: plat, Control: "sendfile", Status: StatusUnavailable, Detail: "x/sys unix.Sendfile returns ENOSYS on OpenBSD; no platform.SendFile path"},
		{ID: "DISC-KQUEUE", Platform: plat, Control: "kqueue_vnode", Status: StatusAvailable, Detail: "platform.VNodeWatch uses kqueue EVFILT_VNODE NOTE_WRITE/DELETE (INT-IC4-0001)"},
	}
}
