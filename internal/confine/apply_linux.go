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

func applyEngineering(role authority.ProcessRole, opts ApplyOptions) []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	var out []Finding
	denyNet := !RoleMayHoldNetwork(role)
	mode := RoleArchiveFSMode(role)

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		out = append(out, Finding{
			ID: "APPLY-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else if set, err := noNewPrivsSet(); err != nil {
		out = append(out, Finding{
			ID: "APPLY-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs",
			Status: StatusUnavailable, Detail: "verify: " + err.Error(),
		})
	} else if !set {
		out = append(out, Finding{
			ID: "APPLY-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs",
			Status: StatusUnavailable, Detail: "PR_SET_NO_NEW_PRIVS left bit unset",
		})
	} else {
		out = append(out, Finding{
			ID: "APPLY-NO-NEW-PRIVS", Platform: plat, Control: "no_new_privs",
			Status: StatusAvailable, Detail: "PR_SET_NO_NEW_PRIVS; PR_GET verified",
		})
	}

	// Clear dumpable (M5x): process-wide; reduces core dumps and complements
	// seccomp ptrace deny without claiming Yama discrimination (NEG-PTRACE).
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		out = append(out, Finding{
			ID: "APPLY-DUMPABLE", Platform: plat, Control: "dumpable",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else if clear, err := dumpableClear(); err != nil {
		out = append(out, Finding{
			ID: "APPLY-DUMPABLE", Platform: plat, Control: "dumpable",
			Status: StatusUnavailable, Detail: "verify: " + err.Error(),
		})
	} else if !clear {
		out = append(out, Finding{
			ID: "APPLY-DUMPABLE", Platform: plat, Control: "dumpable",
			Status: StatusUnavailable, Detail: "PR_SET_DUMPABLE(0) left process dumpable",
		})
	} else {
		out = append(out, Finding{
			ID: "APPLY-DUMPABLE", Platform: plat, Control: "dumpable",
			Status: StatusAvailable, Detail: "PR_SET_DUMPABLE(0); PR_GET verified",
		})
	}

	// Disable core dumps via RLIMIT_CORE=0 (M5z): process-wide; complements
	// dumpable clear. Does not claim to stop all privileged/pipe coredump paths.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		out = append(out, Finding{
			ID: "APPLY-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else if zero, err := rlimitCoreZero(); err != nil {
		out = append(out, Finding{
			ID: "APPLY-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
			Status: StatusUnavailable, Detail: "verify: " + err.Error(),
		})
	} else if !zero {
		out = append(out, Finding{
			ID: "APPLY-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
			Status: StatusUnavailable, Detail: "RLIMIT_CORE left soft or hard non-zero",
		})
	} else {
		out = append(out, Finding{
			ID: "APPLY-RLIMIT-CORE", Platform: plat, Control: "rlimit_core",
			Status: StatusAvailable, Detail: "RLIMIT_CORE soft=hard=0; getrlimit verified",
		})
	}

	// Clear ambient capability set (M5u). Does not empty permitted/effective/
	// bounding sets — dedicated account residual remains for full empty caps.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		out = append(out, Finding{
			ID: "APPLY-CAP-AMBIENT", Platform: plat, Control: "empty_capability_set",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else if empty, err := ambientCapsEmpty(); err != nil {
		out = append(out, Finding{
			ID: "APPLY-CAP-AMBIENT", Platform: plat, Control: "empty_capability_set",
			Status: StatusUnavailable, Detail: "verify: " + err.Error(),
		})
	} else if !empty {
		out = append(out, Finding{
			ID: "APPLY-CAP-AMBIENT", Platform: plat, Control: "empty_capability_set",
			Status: StatusUnavailable, Detail: "PR_CAP_AMBIENT_CLEAR_ALL left ambient caps set",
		})
	} else {
		out = append(out, Finding{
			ID: "APPLY-CAP-AMBIENT", Platform: plat, Control: "empty_capability_set",
			Status: StatusAvailable, Detail: "PR_CAP_AMBIENT_CLEAR_ALL; CapAmb verified empty",
		})
	}

	abi, err := landlockABIVersion()
	if err != nil {
		out = append(out, Finding{
			ID: "APPLY-LANDLOCK", Platform: plat, Control: "landlock",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else if err := landlockApplyFS(abi, mode, opts.AllowRoots); err != nil {
		out = append(out, Finding{
			ID: "APPLY-LANDLOCK", Platform: plat, Control: "landlock",
			Status: StatusUnavailable, Detail: fmt.Sprintf("abi=%d: %v", abi, err),
		})
	} else {
		detail := fmt.Sprintf("abi=%d", abi)
		if mode == ArchiveFSNone || len(opts.AllowRoots) == 0 {
			detail += " empty ruleset (deny new FS opens)"
		} else {
			detail += fmt.Sprintf(" allow-roots=%d mode=%d", len(opts.AllowRoots), mode)
		}
		out = append(out, Finding{
			ID: "APPLY-LANDLOCK", Platform: plat, Control: "landlock",
			Status: StatusAvailable, Detail: detail,
		})
	}

	if err := seccompDenyEngineering(denyNet); err != nil {
		out = append(out, Finding{
			ID: "APPLY-SECCOMP", Platform: plat, Control: "seccomp_bpf",
			Status: StatusUnavailable, Detail: err.Error(),
		})
	} else if filter, err := seccompModeFilter(); err != nil {
		out = append(out, Finding{
			ID: "APPLY-SECCOMP", Platform: plat, Control: "seccomp_bpf",
			Status: StatusUnavailable, Detail: "verify: " + err.Error(),
		})
	} else if !filter {
		out = append(out, Finding{
			ID: "APPLY-SECCOMP", Platform: plat, Control: "seccomp_bpf",
			Status: StatusUnavailable, Detail: "PR_GET_SECCOMP not SECCOMP_MODE_FILTER after TSYNC",
		})
	} else {
		detail := "SECCOMP_SET_MODE_FILTER+TSYNC; deny execve/execveat/ptrace (ERRNO EPERM)"
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

func landlockApplyFS(abi int, mode ArchiveFSMode, roots []string) error {
	access := landlockHandledFS(abi)
	attr := unix.LandlockRulesetAttr{Access_fs: access}
	fd, err := landlockCreateRuleset(&attr)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if mode != ArchiveFSNone && len(roots) > 0 {
		allowed := landlockRootAccess(abi, mode)
		for _, root := range roots {
			dirfd, err := unix.Open(root, unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			rule := unix.LandlockPathBeneathAttr{
				Allowed_access: allowed,
				Parent_fd:      int32(dirfd),
			}
			_, _, errno := unix.Syscall(
				unix.SYS_LANDLOCK_ADD_RULE,
				uintptr(fd),
				uintptr(unix.LANDLOCK_RULE_PATH_BENEATH),
				uintptr(unsafe.Pointer(&rule)),
			)
			_ = unix.Close(dirfd)
			if errno != 0 {
				return errno
			}
		}
	}
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func landlockRootAccess(abi int, mode ArchiveFSMode) uint64 {
	access := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	if mode == ArchiveFSReadWrite {
		access |= unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM
		if abi >= 3 {
			access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
		}
	}
	return access
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

// seccompDenyEngineering installs a process-wide filter that returns EPERM for
// execve/execveat/ptrace (and optionally network syscalls) so in-child
// negative probes can observe the denial without being killed.
// Uses SECCOMP_FILTER_FLAG_TSYNC so all existing threads inherit the filter
// (M5w); PR_SET_SECCOMP alone would confine only the calling thread.
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
	deny := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	allow := uint32(unix.SECCOMP_RET_ALLOW)
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
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// seccompModeFilter reports whether the process is in SECCOMP_MODE_FILTER.
func seccompModeFilter() (bool, error) {
	v, err := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	if err != nil {
		return false, err
	}
	return v == int(unix.SECCOMP_MODE_FILTER), nil
}
