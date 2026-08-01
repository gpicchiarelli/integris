//go:build linux

package confine

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/gpicchiarelli/integris/internal/authority"
	"golang.org/x/sys/unix"
)

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	var out []Finding
	abi, err := landlockABIVersion()
	if err != nil {
		out = append(out, Finding{
			ID: "PROBE-LANDLOCK-ABI", Platform: plat, Control: "landlock",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else {
		out = append(out, Finding{
			ID: "PROBE-LANDLOCK-ABI", Platform: plat, Control: "landlock",
			Status: StatusAvailable, Detail: fmt.Sprintf("abi=%d", abi),
		})
	}
	if arch, ok := seccompAuditArch(); ok {
		out = append(out, Finding{
			ID: "PROBE-SECCOMP-ARCH", Platform: plat, Control: "seccomp_bpf",
			Status: StatusAvailable, Detail: fmt.Sprintf("audit_arch=0x%x", arch),
		})
	} else {
		out = append(out, Finding{
			ID: "PROBE-SECCOMP-ARCH", Platform: plat, Control: "seccomp_bpf",
			Status: StatusSkipped, Detail: "seccomp filter not defined for GOARCH",
		})
	}
	return out
}

func applyEngineering(role authority.ProcessRole) []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	var out []Finding
	denyNet := !RoleMayHoldNetwork(role)

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		out = append(out, Finding{
			ID: "APPLY-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else {
		out = append(out, Finding{
			ID: "APPLY-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs",
			Status: StatusAvailable, Detail: "PR_SET_NO_NEW_PRIVS set",
		})
	}

	abi, err := landlockABIVersion()
	if err != nil {
		out = append(out, Finding{
			ID: "APPLY-LANDLOCK", Platform: plat, Control: "landlock",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else if err := landlockDenyNewFS(abi); err != nil {
		out = append(out, Finding{
			ID: "APPLY-LANDLOCK", Platform: plat, Control: "landlock",
			Status: StatusUnavailable, Detail: fmt.Sprintf("abi=%d: %v", abi, err),
		})
	} else {
		out = append(out, Finding{
			ID: "APPLY-LANDLOCK", Platform: plat, Control: "landlock",
			Status: StatusAvailable, Detail: fmt.Sprintf("abi=%d empty ruleset (deny new FS opens)", abi),
		})
	}

	if err := seccompDenyEngineering(denyNet); err != nil {
		out = append(out, Finding{
			ID: "APPLY-SECCOMP", Platform: plat, Control: "seccomp_bpf",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else {
		detail := "deny execve/execveat/ptrace (ERRNO EPERM)"
		if denyNet {
			detail += "; deny socket/connect/bind/listen/accept*"
		}
		out = append(out, Finding{
			ID: "APPLY-SECCOMP", Platform: plat, Control: "seccomp_bpf",
			Status: StatusAvailable, Detail: detail,
		})
	}
	return out
}

func landlockABIVersion() (int, error) {
	r1, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0, 0, uintptr(unix.LANDLOCK_CREATE_RULESET_VERSION),
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}

func landlockDenyNewFS(abi int) error {
	access := landlockHandledFS(abi)
	attr := unix.LandlockRulesetAttr{Access_fs: access}
	fd, err := landlockCreateRuleset(&attr)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func landlockCreateRuleset(attr *unix.LandlockRulesetAttr) (int, error) {
	r1, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
		0,
	)
	if errno != 0 {
		return -1, errno
	}
	return int(r1), nil
}

func landlockHandledFS(abi int) uint64 {
	access := uint64(
		unix.LANDLOCK_ACCESS_FS_EXECUTE |
			unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM,
	)
	if abi >= 2 {
		access |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		access |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return access
}

func seccompAuditArch() (uint32, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, true
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, true
	default:
		return 0, false
	}
}

// seccompDenyEngineering installs a filter that returns EPERM for
// execve/execveat/ptrace (and optionally network syscalls) so in-child
// negative probes can observe the denial without being killed.
func seccompDenyEngineering(denyNet bool) error {
	arch, ok := seccompAuditArch()
	if !ok {
		return fmt.Errorf("unsupported GOARCH %s", runtime.GOARCH)
	}
	denyNRs := []uint32{
		uint32(unix.SYS_EXECVE),
		uint32(unix.SYS_EXECVEAT),
		uint32(unix.SYS_PTRACE),
	}
	if denyNet {
		denyNRs = append(denyNRs,
			uint32(unix.SYS_SOCKET),
			uint32(unix.SYS_CONNECT),
			uint32(unix.SYS_BIND),
			uint32(unix.SYS_LISTEN),
			uint32(unix.SYS_ACCEPT),
			uint32(unix.SYS_ACCEPT4),
		)
	}
	const (
		offNR   = 0
		offArch = 4
	)
	deny := unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	allow := unix.SECCOMP_RET_ALLOW
	ldAbs := uint16(unix.BPF_LD | unix.BPF_W | unix.BPF_ABS)
	jmpJEQ := uint16(unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K)
	retK := uint16(unix.BPF_RET | unix.BPF_K)

	filter := []unix.SockFilter{
		{Code: ldAbs, K: offArch},
		{Code: jmpJEQ, Jt: 1, Jf: 0, K: arch},
		{Code: retK, K: deny},
		{Code: ldAbs, K: offNR},
	}
	for _, nr := range denyNRs {
		filter = append(filter,
			unix.SockFilter{Code: jmpJEQ, Jt: 0, Jf: 1, K: nr},
			unix.SockFilter{Code: retK, K: deny},
		)
	}
	filter = append(filter, unix.SockFilter{Code: retK, K: allow})
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	_, _, errno := unix.Syscall(
		unix.SYS_PRCTL,
		uintptr(unix.PR_SET_SECCOMP),
		uintptr(unix.SECCOMP_MODE_FILTER),
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
