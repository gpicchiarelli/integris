//go:build darwin

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-HARDENED-RUNTIME", Platform: plat, Control: "hardened_runtime", Status: StatusUnknown, Detail: "requires signed binary inspection"},
		{ID: "DISC-SANDBOX", Platform: plat, Control: "app_sandbox", Status: StatusUnknown, Detail: "deployment-dependent; not claimed equivalent to capability mode"},
		{ID: "DISC-SEATBELT", Platform: plat, Control: "seatbelt", Status: StatusAvailable, Detail: "engineering ApplyEngineering uses sandbox_init when CGO enabled"},
		{ID: "DISC-LAUNCHD-IDENTITY", Platform: plat, Control: "dedicated_identity", Status: StatusUnavailable, Detail: "no launchd child identities until spawn adapter"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available in-process via OpenSocketFabric"},
		{ID: "DISC-KEY-FD", Platform: plat, Control: "sealed_mac_key_fd", Status: StatusUnknown, Detail: "launcher.CreateKeyFD uses anon-unlinked FD; memfd seals unavailable on Darwin"},
		{ID: "DISC-FULLFSYNC", Platform: plat, Control: "durable_sync", Status: StatusAvailable, Detail: "platform.SyncFile uses F_FULLFSYNC (INT-IC4-0001)"},
		{ID: "DISC-CLONEFILE", Platform: plat, Control: "clonefile", Status: StatusAvailable, Detail: "platform.CloneFile prefers clonefile; degraded copy uses sparse SEEK_DATA/HOLE + CopyXattr+CopyBSDFlags+CopyACL+CopyResourceFork+CopyTimes (INT-IC4-0001)"},
		{ID: "DISC-SPARSE", Platform: plat, Control: "sparse_extents", Status: StatusAvailable, Detail: "platform copyFileContents uses SEEK_DATA/SEEK_HOLE on CloneFile degraded copy (INT-IC4-0001 / CapSparse)"},
		{ID: "DISC-ACL", Platform: plat, Control: "extended_acl", Status: StatusAvailable, Detail: "platform.ACLRoundTrip/CopyACL use acl_* when CGO enabled; CopyACL on CloneFile degraded copy (INT-IC4-0001 / CapACL)"},
		{ID: "DISC-XATTR", Platform: plat, Control: "extended_attributes", Status: StatusAvailable, Detail: "platform.CopyXattr (listxattr/getxattr/setxattr) on CloneFile degraded copy (INT-IC4-0001 / CapXattr)"},
		{ID: "DISC-BSDFLAGS", Platform: plat, Control: "bsd_file_flags", Status: StatusAvailable, Detail: "platform.CopyBSDFlags (chflags) on CloneFile degraded copy (INT-IC4-0001 / CapBSDFlags)"},
		{ID: "DISC-RFORK", Platform: plat, Control: "resource_fork", Status: StatusAvailable, Detail: "platform.CopyResourceFork (..namedfork/rsrc) on CloneFile degraded copy (INT-IC4-0001 / CapResourceFork)"},
		{ID: "DISC-TIMES", Platform: plat, Control: "atime_mtime", Status: StatusAvailable, Detail: "platform.CopyTimes + degraded-copy SyncFile/UtimesNano (INT-IC4-0001 / CapTimes)"},
	}
}
