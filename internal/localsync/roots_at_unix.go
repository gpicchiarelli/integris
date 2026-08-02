//go:build unix

package localsync

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// resolveRootsAt validates conferred directory FDs and returns cleaned path labels.
// Ambient Lstat is skipped (CapEnter-safe). Nesting checks use path labels only.
func resolveRootsAt(source, destination string, srcFD, dstFD *os.File) (Roots, error) {
	if srcFD == nil || dstFD == nil {
		return Roots{}, invalidArg("roots", "nil source or destination fd")
	}
	if strings.TrimSpace(source) == "" {
		return Roots{}, invalidArg("roots", "source is required")
	}
	if strings.TrimSpace(destination) == "" {
		return Roots{}, invalidArg("roots", "destination is required")
	}
	srcAbs, err := absClean(source)
	if err != nil {
		return Roots{}, wrap(KindInvalidArgument, "roots", "", err)
	}
	dstAbs, err := absClean(destination)
	if err != nil {
		return Roots{}, wrap(KindInvalidArgument, "roots", "", err)
	}
	if srcAbs == dstAbs {
		return Roots{}, pathUnsafe("roots", "source and destination are the same path")
	}
	if err := fstatDirFD(srcFD, "source"); err != nil {
		return Roots{}, err
	}
	if err := fstatDirFD(dstFD, "destination"); err != nil {
		return Roots{}, err
	}
	if isNested(srcAbs, dstAbs) {
		return Roots{}, pathUnsafe("roots", "destination is inside source")
	}
	if isNested(dstAbs, srcAbs) {
		metaAbs := filepath.Join(dstAbs, MetaDirName)
		if srcAbs != metaAbs && !isNested(metaAbs, srcAbs) {
			return Roots{}, pathUnsafe("roots", "source is inside destination")
		}
	}
	return Roots{Source: srcAbs, Destination: dstAbs}, nil
}

func fstatDirFD(f *os.File, label string) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return wrap(KindRead, "roots", label, err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return pathUnsafe("roots", label+" must not be a symbolic link")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return invalidArg("roots", label+" must be a directory")
	}
	return nil
}

func ensureMetaReadyAt(destFD *os.File) error {
	metaFD, err := ensureMetaDirAt(int(destFD.Fd()))
	if err != nil {
		return err
	}
	_ = unix.Close(metaFD)
	return nil
}
