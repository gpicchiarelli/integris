//go:build freebsd

package confine

import (
	"os"
	"runtime"

	"github.com/gpicchiarelli/integris/internal/authority"
	"golang.org/x/sys/unix"
)

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		{
			ID: "PROBE-CAPSICUM", Platform: plat, Control: "cap_enter",
			Status: StatusAvailable, Detail: "cap_enter(2) available",
		},
		{
			ID: "PROBE-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit",
			Status: StatusAvailable, Detail: "cap_rights_limit(2) available",
		},
	}
}

// LimitConferredFDs reduces IPC/key fds to read/write/event before CapEnter.
func LimitConferredFDs(files ...*os.File) Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	rights, err := unix.CapRightsInit([]uint64{unix.CAP_READ, unix.CAP_WRITE, unix.CAP_EVENT})
	if err != nil {
		return Finding{
			ID: "APPLY-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		if err := unix.CapRightsLimit(f.Fd(), rights); err != nil {
			return Finding{
				ID: "APPLY-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit",
				Status: StatusUnavailable, Detail: err.Error(),
			}
		}
	}
	return Finding{
		ID: "APPLY-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit",
		Status: StatusAvailable, Detail: "CAP_READ|CAP_WRITE|CAP_EVENT on conferred fds",
	}
}

func applyEngineering(role authority.ProcessRole, opts ApplyOptions) []Finding {
	_ = opts // Capsicum is fd-only; path allow-lists require pre-conferred directory FDs.
	_ = role
	plat := runtime.GOOS + "/" + runtime.GOARCH
	if err := unix.CapEnter(); err != nil {
		return []Finding{{
			ID: "APPLY-CAPSICUM", Platform: plat, Control: "cap_enter",
			Status: StatusUnavailable, Detail: err.Error(),
		}}
	}
	return []Finding{{
		ID: "APPLY-CAPSICUM", Platform: plat, Control: "cap_enter",
		Status: StatusAvailable, Detail: "capability mode entered (fd-only; path allow-lists N/A)",
	}}
}
