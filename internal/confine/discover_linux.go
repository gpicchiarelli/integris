//go:build linux

package confine

import "runtime"

func discoverPlatform() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{ID: "DISC-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs", Status: StatusUnknown, Detail: "applied in child via confine.ApplyEngineering"},
		{ID: "DISC-LANDLOCK", Platform: plat, Control: "landlock", Status: StatusUnknown, Detail: "ABI probed via confine.ProbeEngineering; applied in child"},
		{ID: "DISC-SECCOMP", Platform: plat, Control: "seccomp_bpf", Status: StatusUnknown, Detail: "filter not installed yet"},
		{ID: "DISC-CAP-EMPTY", Platform: plat, Control: "empty_capability_set", Status: StatusUnknown, Detail: "ambient caps not cleared until dedicated account spawn"},
		{ID: "DISC-PREOPEN-FD", Platform: plat, Control: "preopened_descriptors", Status: StatusAvailable, Detail: "socketpair endpoints available in-process via OpenSocketFabric"},
	}
}
