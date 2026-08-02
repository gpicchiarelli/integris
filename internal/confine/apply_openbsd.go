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
// children: stdio + AF_UNIX IPC (incl. SCM_RIGHTS) always; inet when CapNetwork;
// rpath/wpath/cpath/fattr when archive allow-roots apply.
func openbsdPromises(role authority.ProcessRole) string {
	parts := []string{"stdio", "unix", "sendfd", "recvfd"}
	if RoleMayHoldNetwork(role) {
		parts = append(parts, "inet")
	}
	switch RoleArchiveFSMode(role) {
	case ArchiveFSReadonly:
		parts = append(parts, "rpath", "fattr")
	case ArchiveFSReadWrite:
		parts = append(parts, "rpath", "wpath", "cpath", "fattr")
	}
	return strings.Join(parts, " ")
}
