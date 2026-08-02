//go:build openbsd

package confine

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/gpicchiarelli/integris/internal/authority"
	"golang.org/x/sys/unix"
)

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{{
		ID: "PROBE-PLEDGE", Platform: plat, Control: "pledge",
		Status: StatusAvailable, Detail: "pledge(2) symbol available",
	}}
}

func applyEngineering(role authority.ProcessRole, opts ApplyOptions) []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	// RLIMIT_CORE before unveil/pledge lock (M6a).
	out := []Finding{applyRlimitCoreFinding(plat)}

	// Unveil before pledge: once pledged without the "unveil" promise,
	// further unveil(2) is denied. Lock the FS view first, then shrink
	// syscall categories.
	mode := RoleArchiveFSMode(role)
	for _, root := range opts.AllowRoots {
		perms := ""
		switch mode {
		case ArchiveFSReadonly:
			perms = "r"
		case ArchiveFSReadWrite:
			perms = "rwc"
		default:
			continue
		}
		if err := unix.Unveil(root, perms); err != nil {
			out = append(out, Finding{
				ID: "APPLY-UNVEIL", Platform: plat, Control: "unveil",
				Status: StatusUnavailable, Detail: fmt.Sprintf("%s: %v", root, err),
			})
			return out
		}
	}
	// Device nodes only beyond AllowRoots; do not unveil /etc (breaks
	// RequireAmbientFSReadDenied on /etc/hosts) or /tmp (ambient write surface).
	if err := unix.Unveil("/dev", "r"); err != nil {
		out = append(out, Finding{
			ID: "APPLY-UNVEIL", Platform: plat, Control: "unveil",
			Status: StatusUnavailable, Detail: "/dev: " + err.Error(),
		})
		return out
	}
	if err := unix.UnveilBlock(); err != nil {
		out = append(out, Finding{
			ID: "APPLY-UNVEIL", Platform: plat, Control: "unveil",
			Status: StatusUnavailable, Detail: err.Error(),
		})
		return out
	}
	detail := "unveil locked"
	if len(opts.AllowRoots) == 0 || mode == ArchiveFSNone {
		detail += " with no paths (fd-only)"
	} else {
		detail += fmt.Sprintf(" allow-roots=%d mode=%d", len(opts.AllowRoots), mode)
	}
	out = append(out, Finding{
		ID: "APPLY-UNVEIL", Platform: plat, Control: "unveil",
		Status: StatusAvailable, Detail: detail,
	})

	promises := openbsdPromises(role)
	if err := unix.PledgePromises(promises); err != nil {
		out = append(out, Finding{
			ID: "APPLY-PLEDGE", Platform: plat, Control: "pledge",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else {
		out = append(out, Finding{
			ID: "APPLY-PLEDGE", Platform: plat, Control: "pledge",
			Status: StatusAvailable, Detail: `promises="` + promises + `"`,
		})
	}
	return out
}

// openbsdPromises is the role-parameterized pledge(2) set for engineering
// children (M5i). Base always includes Go-runtime survival + AF_UNIX IPC;
// locked unveil remains the primary ambient FS boundary. FS write categories
// follow RoleArchiveFSMode. Non-net roles omit inet; exec is omitted (NEG-EXEC
// is promise-omission). Do not include "tmppath" (removed from pledgenames →
// EINVAL) or "dns" (BYPASSUNVEIL for /etc/hosts under OpenBSD 7.8).
func openbsdPromises(role authority.ProcessRole) string {
	parts := []string{"stdio", "rpath", "unix", "sendfd", "recvfd", "proc"}
	switch RoleArchiveFSMode(role) {
	case ArchiveFSReadWrite:
		parts = append(parts, "wpath", "cpath", "fattr", "flock")
	}
	if RoleMayHoldNetwork(role) {
		parts = append(parts, "inet")
	}
	return strings.Join(parts, " ")
}
