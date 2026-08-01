//go:build linux

package confine

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

func probeEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	abi, err := landlockABIVersion()
	if err != nil {
		return []Finding{{
			ID: "PROBE-LANDLOCK-ABI", Platform: plat, Control: "landlock",
			Status: StatusUnavailable, Detail: err.Error(),
		}}
	}
	return []Finding{{
		ID: "PROBE-LANDLOCK-ABI", Platform: plat, Control: "landlock",
		Status: StatusAvailable, Detail: fmt.Sprintf("abi=%d", abi),
	}}
}

func applyEngineering() []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	var out []Finding

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
		return out
	}
	if err := landlockDenyNewFS(abi); err != nil {
		out = append(out, Finding{
			ID: "APPLY-LANDLOCK", Platform: plat, Control: "landlock",
			Status: StatusUnavailable, Detail: fmt.Sprintf("abi=%d: %v", abi, err),
		})
		return out
	}
	out = append(out, Finding{
		ID: "APPLY-LANDLOCK", Platform: plat, Control: "landlock",
		Status: StatusAvailable, Detail: fmt.Sprintf("abi=%d empty ruleset (deny new FS opens)", abi),
	})
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
