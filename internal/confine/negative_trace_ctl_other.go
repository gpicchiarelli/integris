//go:build !freebsd

package confine

import "runtime"

// NegativeTraceCtl is FreeBSD-only (procctl PROC_TRACE_STATUS); skipped elsewhere.
func NegativeTraceCtl() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-TRACE-CTL", Platform: plat, Control: "proc_trace_ctl",
		Status: StatusSkipped, Detail: "PROC_TRACE_CTL probe is FreeBSD-only",
	}
}
