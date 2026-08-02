//go:build unix

package remotesync

import (
	"errors"
	"os"

	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"golang.org/x/sys/unix"
)

// BootstrapJournalAt creates .integris/local.jrn via openat on destFD (M3l).
// Used before CapEnter so later ServeJournalIPC reopen can stay CapEnter-safe.
// destFD is borrowed.
func BootstrapJournalAt(destFD *os.File) error {
	if destFD == nil {
		return fail(KindInvalidArgument, "nil dest fd for journal bootstrap")
	}
	dfd := int(destFD.Fd())
	if err := mkdiratOneJournal(dfd, localsync.MetaDirName, 0o700); err != nil {
		return wrap(KindInternal, "journal meta", err)
	}
	metaFD, err := unix.Openat(dfd, localsync.MetaDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return wrap(KindInternal, "journal meta open", err)
	}
	defer unix.Close(metaFD)

	seg, err := journal.OpenFileSegmentAt(metaFD, localsync.JournalFileName)
	if err != nil {
		return wrap(KindInternal, "journal bootstrap", err)
	}
	return seg.Close()
}

func mkdiratOneJournal(dirfd int, name string, perm uint32) error {
	if err := unix.Mkdirat(dirfd, name, perm); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}
