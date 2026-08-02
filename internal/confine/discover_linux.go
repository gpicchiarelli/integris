//go:build linux

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs", Status: StatusAvailable, Detail: "ApplyEngineering sets PR_NO_NEW_PRIVS and verifies via PR_GET (M5v)"},
		{ID: "DISC-DUMPABLE", Platform: plat, Control: "dumpable", Status: StatusAvailable, Detail: "ApplyEngineering clears PR_DUMPABLE via PR_SET_DUMPABLE(0) and verifies PR_GET (M5x)"},
		{ID: "DISC-LANDLOCK", Platform: plat, Control: "landlock", Status: StatusUnknown, Detail: "ABI probed via confine.ProbeEngineering; applied in child (per-thread residual for threads created before restrict)"},
		{ID: "DISC-SECCOMP", Platform: plat, Control: "seccomp_bpf", Status: StatusAvailable, Detail: "ApplyEngineering installs SECCOMP_SET_MODE_FILTER+TSYNC and verifies PR_GET_SECCOMP (M5w)"},
		{ID: "DISC-CAP-AMBIENT", Platform: plat, Control: "ambient_capability_clear", Status: StatusAvailable, Detail: "ApplyEngineering clears ambient via PR_CAP_AMBIENT_CLEAR_ALL (M5u)"},
		{ID: "DISC-CAP-EMPTY", Platform: plat, Control: "empty_capability_set", Status: StatusUnavailable, Detail: "full empty permitted/effective/bounding needs CAP_SETPCAP or dedicated account; ambient clear only (M5u residual)"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available in-process via OpenSocketFabric"},
		{ID: "DISC-KEY-FD", Platform: plat, Control: "sealed_mac_key_fd", Status: StatusAvailable, Detail: "launcher.CreateKeyFD uses sealed memfd (F_SEAL_WRITE|SHRINK|GROW|SEAL)"},
		{ID: "DISC-SENDFILE", Platform: plat, Control: "sendfile", Status: StatusAvailable, Detail: "platform.SendFile uses sendfile(2) to a connected socket (socketpair harness; INT-IC4-0001)"},
		{ID: "DISC-KQUEUE", Platform: plat, Control: "kqueue_vnode", Status: StatusUnavailable, Detail: "kqueue absent on Linux; platform.VNodeWatch uses inotify (DISC-INOTIFY)"},
		{ID: "DISC-INOTIFY", Platform: plat, Control: "inotify_vnode", Status: StatusAvailable, Detail: "platform.VNodeWatch uses inotify IN_MODIFY/IN_CLOSE_WRITE and IN_DELETE_SELF (INT-IC4-0001)"},
		{ID: "DISC-ACL", Platform: plat, Control: "posix_acl", Status: StatusAvailable, Detail: "platform.ACLRoundTrip/CopyACL use system.posix_acl_access xattr (INT-IC4-0001 / CapACL)"},
	}
}
