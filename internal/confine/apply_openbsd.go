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
	var out []Finding
	promises := openbsdPromises(role)
	if err := unix.Pledge(promises, ""); err != nil {
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
	// Go runtime helpers and common devices; archive AllowRoots as above.
	for _, p := range []struct{ path, perms string }{
		{"/dev", "r"},
		{"/tmp", "rwc"},
		{"/etc", "r"},
	} {
		if err := unix.Unveil(p.path, p.perms); err != nil {
			out = append(out, Finding{
				ID: "APPLY-UNVEIL", Platform: plat, Control: "unveil",
				Status: StatusUnavailable, Detail: fmt.Sprintf("%s: %v", p.path, err),
			})
			return out
		}
	}
	if err := unix.UnveilBlock(); err != nil {
		out = append(out, Finding{
			ID: "APPLY-UNVEIL", Platform: plat, Control: "unveil",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else {
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
	}
	return out
}

// openbsdPromises is the role-parameterized pledge(2) set for engineering
// children. M4y first cut keeps a broad promise set so the Go runtime and
// supervised receive path survive; locked unveil remains the primary ambient
// FS boundary. Non-net roles omit inet; exec is omitted (NEG-EXEC is
// promise-omission on OpenBSD). Tightening is a documented follow-on.
func openbsdPromises(role authority.ProcessRole) string {
	parts := []string{
		"stdio", "rpath", "wpath", "cpath", "tmppath",
		"unix", "sendfd", "recvfd", "dns", "proc", "fattr", "flock",
	}
	if RoleMayHoldNetwork(role) {
		parts = append(parts, "inet")
	}
	return strings.Join(parts, " ")
}
