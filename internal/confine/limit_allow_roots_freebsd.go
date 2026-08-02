//go:build freebsd

package confine

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// LimitAllowRootFDs applies Capsicum directory rights for conferred archive
// roots before CapEnter. Readonly roles get lookup/read/stat; read-write also
// gets create/write/unlinkat plus mkdirat/renameat/fsync/fchmod for staging (M3e).
// CapRightsGet verifies want present and write/create (or network/exec
// sentinels) absent as appropriate (M5y).
func LimitAllowRootFDs(mode ArchiveFSMode, files ...*os.File) Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	if mode == ArchiveFSNone || len(files) == 0 {
		return Finding{
			ID: "APPLY-CAP-ALLOW-ROOTS", Platform: plat, Control: "cap_rights_limit",
			Status: StatusSkipped, Detail: "no allow-root directory fds",
		}
	}
	want := []uint64{
		unix.CAP_LOOKUP,
		unix.CAP_READ,
		unix.CAP_SEEK,
		unix.CAP_FSTAT,
		unix.CAP_FSTATAT,
	}
	detail := "CAP_LOOKUP|READ|SEEK|FSTAT|FSTATAT"
	var absent []uint64
	if mode == ArchiveFSReadWrite {
		want = append(want,
			unix.CAP_CREATE, unix.CAP_WRITE, unix.CAP_UNLINKAT,
			unix.CAP_MKDIRAT, unix.CAP_RENAMEAT_SOURCE, unix.CAP_RENAMEAT_TARGET,
			unix.CAP_FSYNC, unix.CAP_FCHMOD, unix.CAP_FCHMODAT, unix.CAP_FTRUNCATE,
		)
		detail += "|CREATE|WRITE|UNLINKAT|MKDIRAT|RENAMEAT|FSYNC|FCHMOD|FTRUNCATE"
		// Directory allow-roots must not retain socket/exec rights.
		absent = []uint64{unix.CAP_ACCEPT, unix.CAP_BIND, unix.CAP_FEXECVE}
	} else {
		// Readonly: prove CREATE/WRITE were removed.
		absent = []uint64{unix.CAP_CREATE, unix.CAP_WRITE, unix.CAP_UNLINKAT}
	}
	rights, err := unix.CapRightsInit(want)
	if err != nil {
		return Finding{
			ID: "APPLY-CAP-ALLOW-ROOTS", Platform: plat, Control: "cap_rights_limit",
			Status: StatusUnavailable, Detail: err.Error(),
		}
	}
	for _, f := range files {
		if f == nil {
			continue
		}
		if err := unix.CapRightsLimit(f.Fd(), rights); err != nil {
			return Finding{
				ID: "APPLY-CAP-ALLOW-ROOTS", Platform: plat, Control: "cap_rights_limit",
				Status: StatusUnavailable, Detail: err.Error(),
			}
		}
		if err := verifyCapRightsLimited(f.Fd(), want, absent); err != nil {
			return Finding{
				ID: "APPLY-CAP-ALLOW-ROOTS", Platform: plat, Control: "cap_rights_limit",
				Status: StatusUnavailable, Detail: "verify: " + err.Error(),
			}
		}
	}
	return Finding{
		ID: "APPLY-CAP-ALLOW-ROOTS", Platform: plat, Control: "cap_rights_limit",
		Status: StatusAvailable, Detail: detail + " on allow-root fds; CapRightsGet verified",
	}
}
