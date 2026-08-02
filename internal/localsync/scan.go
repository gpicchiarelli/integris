package localsync

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gpicchiarelli/integris/internal/path"
)

// Manifest is a deterministic, sorted scan of a sync root.
type Manifest struct {
	Root    string
	Entries []Entry
}

// Scan walks root without following symbolic links. Symlinks and special files
// are refused with KindUnsupported. Entries are sorted by Rel ascending.
func Scan(root string) (Manifest, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return Manifest{}, wrap(KindRead, "scan", "", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, pathUnsafe("scan", "root must not be a symbolic link")
	}
	if !info.IsDir() {
		return Manifest{}, invalidArg("scan", "root must be a directory")
	}

	var entries []Entry
	err = filepath.WalkDir(root, func(native string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return wrap(KindRead, "scan", "", walkErr)
		}
		if native == root {
			return nil
		}
		rel, err := filepath.Rel(root, native)
		if err != nil {
			return wrap(KindInternal, "scan", "", err)
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || rel == "" {
			return nil
		}
		if strings.HasPrefix(rel, "../") || rel == ".." {
			return pathUnsafe("scan", "path escapes root")
		}
		if isMetaRel(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		comps, err := path.ValidateJoined(rel, path.DefaultProfile)
		if err != nil {
			return classify(KindPathUnsafe, "scan", rel, "logical path rejected by grammar", err)
		}
		_ = comps

		fi, err := d.Info()
		if err != nil {
			return wrap(KindRead, "scan", rel, err)
		}
		mode := fi.Mode()

		switch {
		case mode&os.ModeSymlink != 0:
			return unsupported("scan", rel, "symbolic link")
		case mode&os.ModeNamedPipe != 0:
			return unsupported("scan", rel, "named pipe")
		case mode&os.ModeSocket != 0:
			return unsupported("scan", rel, "socket")
		case mode&os.ModeDevice != 0:
			return unsupported("scan", rel, "device")
		case mode.IsDir():
			entries = append(entries, Entry{
				Rel:  rel,
				Type: EntryDir,
				Mode: uint32(mode.Perm()),
			})
			return nil
		case mode.IsRegular():
			dig, size, err := HashFile(native)
			if err != nil {
				return wrap(KindRead, "scan", rel, err)
			}
			entries = append(entries, Entry{
				Rel:       rel,
				Type:      EntryFile,
				Size:      size,
				Mode:      uint32(mode.Perm()),
				Digest:    dig,
				HasDigest: true,
			})
			return nil
		default:
			return unsupported("scan", rel, "unsupported file type")
		}
	})
	if err != nil {
		return Manifest{}, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Rel < entries[j].Rel
	})
	return Manifest{Root: root, Entries: entries}, nil
}

// lookup returns the entry with Rel == rel, or false.
func (m Manifest) lookup(rel string) (Entry, bool) {
	// binary search; Entries sorted
	i := sort.Search(len(m.Entries), func(i int) bool {
		return m.Entries[i].Rel >= rel
	})
	if i < len(m.Entries) && m.Entries[i].Rel == rel {
		return m.Entries[i], true
	}
	return Entry{}, false
}
