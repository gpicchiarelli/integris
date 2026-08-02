//go:build freebsd

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-CAPSICUM", Platform: plat, Control: "cap_enter", Status: StatusUnknown, Detail: "applied in child via confine.ApplyEngineering"},
		{ID: "DISC-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit", Status: StatusUnknown, Detail: "LimitConferredFDs applies CAP_READ|WRITE|EVENT before cap_enter"},
		{ID: "DISC-ALLOW-ROOT-FD", Platform: plat, Control: "conferred_directory_fds", Status: StatusAvailable, Detail: "launcher ExtraFiles + INTEGRIS_ALLOW_ROOT_FDS; LimitAllowRootFDs before cap_enter; NEG-FS-PATH/WRITE via openat"},
		{ID: "DISC-JAIL-NOIP", Platform: plat, Control: "jail_set_ip_disable", Status: StatusAvailable, Detail: "non-net roles: jail_set CREATE|ATTACH path=/ ip4=disable ip6=disable nopersist before cap_enter (M3s NEG-ROLE-NET)"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available via OpenSocketFabric"},
		{ID: "DISC-KEY-FD", Platform: plat, Control: "sealed_mac_key_fd", Status: StatusUnknown, Detail: "launcher.CreateKeyFD uses anon-unlinked FD; FreeBSD memfd seals not wired yet"},
		{ID: "DISC-SENDFILE", Platform: plat, Control: "sendfile", Status: StatusAvailable, Detail: "platform.SendFile uses sendfile(2) to a connected socket (socketpair harness; INT-IC4-0001)"},
		{ID: "DISC-KQUEUE", Platform: plat, Control: "kqueue_vnode", Status: StatusAvailable, Detail: "platform.VNodeWatch uses kqueue EVFILT_VNODE NOTE_WRITE/DELETE (INT-IC4-0001)"},
	}
}
