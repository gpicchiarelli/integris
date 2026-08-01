//go:build !unix

package confine

import (
	"runtime"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// NegativeExec is unavailable off Unix.
func NegativeExec() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-EXEC", Platform: plat, Control: "process_exec",
		Status: StatusSkipped, Detail: "unix only",
	}
}

// NegativePtrace is unavailable off Unix.
func NegativePtrace() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-PTRACE", Platform: plat, Control: "ptrace",
		Status: StatusSkipped, Detail: "unix only",
	}
}

// NegativeRoleNet is unavailable off Unix.
func NegativeRoleNet(role authority.ProcessRole) Finding {
	_ = role
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return Finding{
		ID: "NEG-ROLE-NET", Platform: plat, Control: "network_sockets",
		Status: StatusSkipped, Detail: "unix only",
	}
}
