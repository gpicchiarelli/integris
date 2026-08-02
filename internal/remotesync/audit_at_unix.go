//go:build unix

package remotesync

import (
	"errors"
	"os"

	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

// AuditSinkFileName is the append-only redacted event sink under .integris/.
const AuditSinkFileName = "audit.events"

// OpenAuditSinkAt creates/opens .integris/audit.events via openat on destFD (M3h).
// Caller owns the returned file. destFD is borrowed.
func OpenAuditSinkAt(destFD *os.File) (*os.File, error) {
	if destFD == nil {
		return nil, fail(KindInvalidArgument, "nil dest fd for audit sink")
	}
	dfd := int(destFD.Fd())
	if err := mkdiratOneAudit(dfd, localsync.MetaDirName, 0o700); err != nil {
		return nil, wrap(KindInternal, "audit meta", err)
	}
	metaFD, err := unix.Openat(dfd, localsync.MetaDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, wrap(KindInternal, "audit meta open", err)
	}
	defer unix.Close(metaFD)

	fd, err := unix.Openat(metaFD, AuditSinkFileName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, wrap(KindInternal, "audit sink open", err)
	}
	return os.NewFile(uintptr(fd), AuditSinkFileName), nil
}

func mkdiratOneAudit(dirfd int, name string, perm uint32) error {
	if err := unix.Mkdirat(dirfd, name, perm); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}
