//go:build freebsd

package confine

import (
	"os"
	"runtime"
	"strconv"

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
		{
			ID: "PROBE-JAIL-NOIP", Platform: plat, Control: "jail_set_ip_disable",
			Status: StatusUnavailable,
			Detail: "CapEnter does not deny AF_INET; jail ip-disable conflicts with allow-root cap_rights_limit (M3s residual)",
		},
	}
}

// LimitConferredFDs reduces IPC/key fds to read/write/event before CapEnter.
// After CapRightsLimit, CapRightsGet must show the expected rights present and
// a sentinel absent (M5y; CAP_FCNTL/CAP_IOCTL M6b); Limit errno alone is not
// sufficient.
func LimitConferredFDs(files ...*os.File) Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	want := []uint64{unix.CAP_READ, unix.CAP_WRITE, unix.CAP_EVENT}
	// Sentinels not in want: prove Limit reduced the mask (IsSet(want) alone
	// passes on an unlimited FD). CAP_FCNTL/CAP_IOCTL close the platform-matrix
	// ioctl/fcntl residual (M6b).
	absent := []uint64{
		unix.CAP_FEXECVE, unix.CAP_ACCEPT, unix.CAP_BIND,
		unix.CAP_FCNTL, unix.CAP_IOCTL,
	}
	rights, err := unix.CapRightsInit(want)
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
		if err := verifyCapRightsLimited(f.Fd(), want, absent); err != nil {
			return Finding{
				ID: "APPLY-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit",
				Status: StatusUnavailable, Detail: "verify: " + err.Error(),
			}
		}
	}
	return Finding{
		ID: "APPLY-CAP-RIGHTS", Platform: plat, Control: "cap_rights_limit",
		Status: StatusAvailable, Detail: "CAP_READ|CAP_WRITE|CAP_EVENT on conferred fds; CapRightsGet verified (FCNTL/IOCTL absent)",
	}
}

func applyEngineering(role authority.ProcessRole, opts ApplyOptions) []Finding {
	_ = role
	plat := runtime.GOOS + "/" + runtime.GOARCH
	// RLIMIT_CORE before CapEnter (M6a): setrlimit remains available pre-mode.
	// PROC_TRACE_CTL_DISABLE before CapEnter (M6c): anti-trace/core parity
	// with Linux dumpable; STATUS verify process-wide.
	out := []Finding{applyRlimitCoreFinding(plat), applyTraceCtlFinding(plat)}
	if err := unix.CapEnter(); err != nil {
		return append(out, Finding{
			ID: "APPLY-CAPSICUM", Platform: plat, Control: "cap_enter",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	}
	detail := "capability mode entered"
	if n := len(opts.AllowRootFDs); n > 0 {
		detail += "; allow-root directory fds=" + strconv.Itoa(n)
	} else if len(opts.AllowRoots) > 0 {
		detail += "; allow-roots paths set but no conferred directory fds"
	}
	return append(out, Finding{
		ID: "APPLY-CAPSICUM", Platform: plat, Control: "cap_enter",
		Status: StatusAvailable, Detail: detail,
	})
}
