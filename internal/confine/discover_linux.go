//go:build linux

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs", Status: StatusUnknown, Detail: "applied in child via confine.ApplyEngineering"},
		{ID: "DISC-LANDLOCK", Platform: plat, Control: "landlock", Status: StatusUnknown, Detail: "ABI probed via confine.ProbeEngineering; applied in child"},
		{ID: "DISC-SECCOMP", Platform: plat, Control: "seccomp_bpf", Status: StatusUnknown, Detail: "exec/ptrace (+network for non-net roles) EPERM denylist applied in child via ApplyEngineering"},
		{ID: "DISC-CAP-EMPTY", Platform: plat, Control: "empty_capability_set", Status: StatusAvailable, Detail: "ApplyEngineering clears ambient via PR_CAP_AMBIENT_CLEAR_ALL (M5u); permitted/effective/bounding + dedicated account residual"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available in-process via OpenSocketFabric"},
		{ID: "DISC-KEY-FD", Platform: plat, Control: "sealed_mac_key_fd", Status: StatusAvailable, Detail: "launcher.CreateKeyFD uses sealed memfd (F_SEAL_WRITE|SHRINK|GROW|SEAL)"},
		{ID: "DISC-SENDFILE", Platform: plat, Control: "sendfile", Status: StatusAvailable, Detail: "platform.SendFile uses sendfile(2) to a connected socket (socketpair harness; INT-IC4-0001)"},
		{ID: "DISC-KQUEUE", Platform: plat, Control: "kqueue_vnode", Status: StatusUnavailable, Detail: "kqueue absent on Linux; platform.VNodeWatch uses inotify (DISC-INOTIFY)"},
		{ID: "DISC-INOTIFY", Platform: plat, Control: "inotify_vnode", Status: StatusAvailable, Detail: "platform.VNodeWatch uses inotify IN_MODIFY/IN_CLOSE_WRITE and IN_DELETE_SELF (INT-IC4-0001)"},
		{ID: "DISC-ACL", Platform: plat, Control: "posix_acl", Status: StatusAvailable, Detail: "platform.ACLRoundTrip/CopyACL use system.posix_acl_access xattr (INT-IC4-0001 / CapACL)"},
	}
}
