package localsync

import (
	"os"
	"path/filepath"
	"strings"
)

// Roots are absolute, cleaned source and destination directories.
type Roots struct {
	Source      string
	Destination string
}

// ResolveRoots validates CLI paths for local sync.
//
// Rules:
//   - both must be existing directories (destination may be absent; caller may create);
//   - must not be the same directory;
//   - destination must not be inside source;
//   - source must not be inside destination, except under destination/.integris/
//     (remotesync recv-stage trees).
//
// allowMissingDest permits destination not to exist yet.
func ResolveRoots(source, destination string, allowMissingDest bool) (Roots, error) {
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

	srcInfo, err := os.Lstat(srcAbs)
	if err != nil {
		return Roots{}, wrap(KindRead, "roots", "", err)
	}
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		return Roots{}, pathUnsafe("roots", "source must not be a symbolic link")
	}
	if !srcInfo.IsDir() {
		return Roots{}, invalidArg("roots", "source must be a directory")
	}

	dstInfo, err := os.Lstat(dstAbs)
	if err != nil {
		if !os.IsNotExist(err) || !allowMissingDest {
			return Roots{}, wrap(KindRead, "roots", "", err)
		}
	} else {
		if dstInfo.Mode()&os.ModeSymlink != 0 {
			return Roots{}, pathUnsafe("roots", "destination must not be a symbolic link")
		}
		if !dstInfo.IsDir() {
			return Roots{}, invalidArg("roots", "destination must be a directory")
		}
	}

	if isNested(srcAbs, dstAbs) {
		return Roots{}, pathUnsafe("roots", "destination is inside source")
	}
	if isNested(dstAbs, srcAbs) {
		// Allow remotesync (and similar) staging trees under destination/.integris/.
		metaAbs := filepath.Join(dstAbs, MetaDirName)
		if srcAbs != metaAbs && !isNested(metaAbs, srcAbs) {
			return Roots{}, pathUnsafe("roots", "source is inside destination")
		}
	}

	return Roots{Source: srcAbs, Destination: dstAbs}, nil
}

func absClean(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// isNested reports whether child is strictly inside parent (same volume path prefix).
func isNested(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	if rel == "." {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
