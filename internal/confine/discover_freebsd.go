//go:build freebsd

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-CAPSICUM", Platform: plat, Control: "cap_enter", Status: StatusAvailable, Detail: "ApplyEngineering CapEnter; RequireCapModeAvailable (M3m)"},
		{ID: "DISC-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit", Status: StatusAvailable, Detail: "LimitConferredFDs/LimitAllowRootFDs + CapRightsGet verify want present and sentinels absent (M5y)"},
		{ID: "DISC-RLIMIT-CORE", Platform: plat, Control: "rlimit_core", Status: StatusAvailable, Detail: "ApplyEngineering sets RLIMIT_CORE soft=hard=0 before CapEnter; getrlimit verified (M6a)"},
		{ID: "DISC-ALLOW-ROOT-FD", Platform: plat, Control: "conferred_directory_fds", Status: StatusAvailable, Detail: "launcher ExtraFiles + INTEGRIS_ALLOW_ROOT_FDS; LimitAllowRootFDs before cap_enter; NEG-FS-PATH/WRITE via openat"},
		{ID: "DISC-JAIL-NOIP", Platform: plat, Control: "jail_set_ip_disable", Status: StatusUnavailable, Detail: "M3s residual: CapEnter leaves AF_INET; jail ip-disable conflicts with allow-root CapRightsLimit"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available via OpenSocketFabric"},
		{ID: "DISC-KEY-FD", Platform: plat, Control: "sealed_mac_key_fd", Status: StatusAvailable, Detail: "launcher.CreateKeyFD uses shm_open2(SHM_ANON)+F_ADD_SEALS (F_SEAL_WRITE|SHRINK|GROW|SEAL)"},
		{ID: "DISC-SENDFILE", Platform: plat, Control: "sendfile", Status: StatusAvailable, Detail: "platform.SendFile uses sendfile(2) to a connected socket (socketpair harness; INT-IC4-0001)"},
		{ID: "DISC-KQUEUE", Platform: plat, Control: "kqueue_vnode", Status: StatusAvailable, Detail: "platform.VNodeWatch uses kqueue EVFILT_VNODE NOTE_WRITE/DELETE (INT-IC4-0001)"},
	}
}
