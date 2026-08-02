//go:build unix

package confine

import (
	"runtime"

	"github.com/gpicchiarelli/integris/internal/authority"
	"golang.org/x/sys/unix"
)

// NegativeExec attempts execve of a well-known path via unix.Exec (not os/exec).
// Under Linux seccomp / OpenBSD pledge / FreeBSD capability mode / Darwin
// Seatbelt this should fail and return.
func NegativeExec() Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	switch runtime.GOOS {
	case "openbsd":
		// unix.Exec without the exec promise terminates with SIGABRT; do not
		// probe in-process. Omission of exec from ApplyEngineering is the deny.
		return Finding{
			ID: "NEG-EXEC", Platform: plat, Control: "process_exec",
			Status: StatusDeniedExpected, Detail: "pledge omits exec (in-process probe would SIGABRT)",
		}
	case "linux", "freebsd", "darwin":
	default:
		return Finding{
			ID: "NEG-EXEC", Platform: plat, Control: "process_exec",
			Status: StatusSkipped, Detail: "no engineering exec denylist on this OS",
		}
	}
	path := "/bin/true"
	if runtime.GOOS == "darwin" {
		path = "/usr/bin/true"
	}
	err := unix.Exec(path, []string{path}, nil)
	// Success replaces the process image and does not return.
	if err == nil {
		return Finding{
			ID: "NEG-EXEC", Platform: plat, Control: "process_exec",
			Status: StatusUnexpectedAllow, Detail: "exec returned nil (unreachable)",
		}
	}
	return Finding{
		ID: "NEG-EXEC", Platform: plat, Control: "process_exec",
		Status: StatusDeniedExpected, Detail: err.Error(),
	}
}

// NegativeRoleNet attempts AF_INET socket use after ApplyEngineering.
// Roles that must not hold CapNetworkSockets should be denied by OS policy
// (Linux seccomp, OpenBSD pledge, Darwin Seatbelt). CapEnter alone does not
// deny AF_INET (FreeBSD M3s residual). CapNetworkSockets holders skip
// (ambient create is not asserted; conferred sockets remain the intended path
// on Capsicum).
func NegativeRoleNet(role authority.ProcessRole) Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	switch runtime.GOOS {
	case "linux", "openbsd", "freebsd", "darwin":
	default:
		return Finding{
			ID: "NEG-ROLE-NET", Platform: plat, Control: "network_sockets",
			Status: StatusSkipped, Detail: "no engineering network denylist on this OS",
		}
	}
	if RoleMayHoldNetwork(role) {
		return Finding{
			ID: "NEG-ROLE-NET", Platform: plat, Control: "network_sockets",
			Status: StatusSkipped, Detail: "role may hold network_sockets; ambient deny not required",
		}
	}
	if runtime.GOOS == "openbsd" {
		// socket(AF_INET) without inet terminates with SIGABRT under pledge.
		return Finding{
			ID: "NEG-ROLE-NET", Platform: plat, Control: "network_sockets",
			Status: StatusDeniedExpected, Detail: "pledge omits inet (in-process probe would SIGABRT)",
		}
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return Finding{
			ID: "NEG-ROLE-NET", Platform: plat, Control: "network_sockets",
			Status: StatusDeniedExpected, Detail: "socket: " + err.Error(),
		}
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrInet4{Port: 9}
	sa.Addr = [4]byte{127, 0, 0, 1}
	err = unix.Connect(fd, sa)
	if err == nil {
		return Finding{
			ID: "NEG-ROLE-NET", Platform: plat, Control: "network_sockets",
			Status: StatusUnexpectedAllow, Detail: "connect to 127.0.0.1:9 succeeded after apply",
		}
	}
	if err == unix.EPERM || err == unix.EACCES {
		return Finding{
			ID: "NEG-ROLE-NET", Platform: plat, Control: "network_sockets",
			Status: StatusDeniedExpected, Detail: "connect: " + err.Error(),
		}
	}
	// ECONNREFUSED / ETIMEDOUT / etc. means the OS allowed the network attempt.
	return Finding{
		ID: "NEG-ROLE-NET", Platform: plat, Control: "network_sockets",
		Status: StatusUnexpectedAllow, Detail: "connect allowed (got " + err.Error() + ")",
	}
}
