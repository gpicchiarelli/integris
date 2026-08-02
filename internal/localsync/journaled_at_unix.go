//go:build unix

package localsync

import (
	"errors"
	"io"
	"os"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/platform"
	"golang.org/x/sys/unix"
)

// openJournalAt opens .integris/local.jrn under destFD via openat when destFD
// is set; otherwise falls back to ambient openJournal(path).
func openJournalAt(destFD *os.File, path string) (*journal.FileSegment, *journal.Writer, journal.Prefix, error) {
	if destFD == nil {
		return openJournal(path)
	}
	metaFD, err := ensureMetaDirAt(int(destFD.Fd()))
	if err != nil {
		return nil, nil, journal.Prefix{}, wrap(KindWrite, "journal", "", err)
	}
	defer unix.Close(metaFD)

	seg, err := journal.OpenFileSegmentAt(metaFD, JournalFileName)
	if err != nil {
		return nil, nil, journal.Prefix{}, wrap(KindWrite, "journal", "", err)
	}
	return finishOpenJournal(seg)
}

func ensureMetaDirAt(destFD int) (metaFD int, err error) {
	if err := mkdiratOne(destFD, MetaDirName, 0o700); err != nil {
		return -1, err
	}
	return unix.Openat(destFD, MetaDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

func mkdiratOne(dirfd int, name string, perm uint32) error {
	if err := unix.Mkdirat(dirfd, name, perm); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

// writePlanSnapshotAt writes last-plan.json under destFD via openat (M3g).
func writePlanSnapshotAt(destFD *os.File, raw []byte) error {
	if destFD == nil {
		return invalidArg("journal", "nil dest fd for plan snapshot")
	}
	metaFD, err := ensureMetaDirAt(int(destFD.Fd()))
	if err != nil {
		return wrap(KindWrite, "journal", "", err)
	}
	defer unix.Close(metaFD)

	tmpName := PlanFileName + ".tmp"
	fd, err := unix.Openat(metaFD, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return wrap(KindWrite, "journal", "", err)
	}
	f := os.NewFile(uintptr(fd), tmpName)
	_, werr := f.Write(raw)
	serr := platform.SyncFile(f)
	cerr := f.Close()
	if werr != nil {
		_ = unix.Unlinkat(metaFD, tmpName, 0)
		return wrap(KindWrite, "journal", "", werr)
	}
	if serr != nil {
		_ = unix.Unlinkat(metaFD, tmpName, 0)
		return wrap(KindWrite, "journal", "", serr)
	}
	if cerr != nil {
		_ = unix.Unlinkat(metaFD, tmpName, 0)
		return wrap(KindWrite, "journal", "", cerr)
	}
	if err := unix.Renameat(metaFD, tmpName, metaFD, PlanFileName); err != nil {
		_ = unix.Unlinkat(metaFD, tmpName, 0)
		return wrap(KindWrite, "journal", "", err)
	}
	_ = unix.Fsync(metaFD)
	return nil
}

func loadPlanSnapshotAt(destFD *os.File) (Plan, codec.Digest, error) {
	if destFD == nil {
		return Plan{}, codec.Digest{}, invalidArg("journal", "nil dest fd for plan snapshot")
	}
	metaFD, err := unix.Openat(int(destFD.Fd()), MetaDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Plan{}, codec.Digest{}, wrap(KindRead, "journal", "", err)
	}
	defer unix.Close(metaFD)
	fd, err := unix.Openat(metaFD, PlanFileName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Plan{}, codec.Digest{}, wrap(KindRead, "journal", "", err)
	}
	f := os.NewFile(uintptr(fd), PlanFileName)
	raw, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return Plan{}, codec.Digest{}, wrap(KindRead, "journal", "", err)
	}
	p, err := ParsePlanJSON(raw)
	if err != nil {
		return Plan{}, codec.Digest{}, err
	}
	return p, codec.SHA256(raw), nil
}
