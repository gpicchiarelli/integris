//go:build linux

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs", Status: StatusUnknown, Detail: "probe requires prctl in confined child"},
		{ID: "DISC-LANDLOCK", Platform: plat, Control: "landlock", Status: StatusUnknown, Detail: "ABI check deferred to platform adapter IP"},
		{ID: "DISC-SECCOMP", Platform: plat, Control: "seccomp_bpf", Status: StatusUnknown, Detail: "filter not installed in engineering process"},
		{ID: "DISC-CAP-EMPTY", Platform: plat, Control: "empty_capability_set", Status: StatusUnknown, Detail: "ambient caps not cleared until spawn"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available in-process via OpenSocketFabric"},
	}
}
