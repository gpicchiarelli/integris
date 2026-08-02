//go:build unix

package localsync

import (
	"os"
	"sort"
	"strings"

	"github.com/gpicchiarelli/integris/internal/path"
	"golang.org/x/sys/unix"
)

// ScanAt walks a directory via openat(2) relative to rootFD (M3d).
// Same semantics as Scan: no symlink follow, refuse specials, skip .integris.
// rootLabel populates Manifest.Root (logging / identity); it is not used for opens.
// rootFD is borrowed (not closed).
func ScanAt(rootFD *os.File, rootLabel string) (Manifest, error) {
	if rootFD == nil {
		return Manifest{}, invalidArg("scanat", "nil root fd")
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(rootFD.Fd()), &st); err != nil {
		return Manifest{}, wrap(KindRead, "scanat", "", err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return Manifest{}, pathUnsafe("scanat", "root must not be a symbolic link")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return Manifest{}, invalidArg("scanat", "root must be a directory")
	}

	var entries []Entry
	if err := scanAtDir(int(rootFD.Fd()), "", &entries); err != nil {
		return Manifest{}, err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Rel < entries[j].Rel
	})
	return Manifest{Root: rootLabel, Entries: entries}, nil
}

func scanAtDir(dirfd int, relPrefix string, entries *[]Entry) error {
	names, err := readDirNamesAt(dirfd)
	if err != nil {
		return wrap(KindRead, "scanat", relPrefix, err)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "." || name == ".." {
			continue
		}
		rel := name
		if relPrefix != "" {
			rel = relPrefix + "/" + name
		}
		if strings.HasPrefix(rel, "../") || rel == ".." {
			return pathUnsafe("scanat", "path escapes root")
		}
		if isMetaRel(rel) {
			continue
		}
		if _, err := path.ValidateJoined(rel, path.DefaultProfile); err != nil {
			return classify(KindPathUnsafe, "scanat", rel, "logical path rejected by grammar", err)
		}

		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOCTTY, 0)
		if err != nil {
			// FreeBSD historically returns EMLINK ("too many links") for
			// O_NOFOLLOW on a symlink; Linux uses ELOOP.
			if err == unix.ELOOP || err == unix.EMLINK {
				return unsupported("scanat", rel, "symbolic link")
			}
			return wrap(KindRead, "scanat", rel, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			_ = unix.Close(fd)
			return wrap(KindRead, "scanat", rel, err)
		}
		mode := fileModeFromStat(uint32(st.Mode))

		switch st.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			_ = unix.Close(fd)
			return unsupported("scanat", rel, "symbolic link")
		case unix.S_IFIFO:
			_ = unix.Close(fd)
			return unsupported("scanat", rel, "named pipe")
		case unix.S_IFSOCK:
			_ = unix.Close(fd)
			return unsupported("scanat", rel, "socket")
		case unix.S_IFBLK, unix.S_IFCHR:
			_ = unix.Close(fd)
			return unsupported("scanat", rel, "device")
		case unix.S_IFDIR:
			*entries = append(*entries, Entry{
				Rel:  rel,
				Type: EntryDir,
				Mode: uint32(mode.Perm()),
			})
			err := scanAtDir(fd, rel, entries)
			_ = unix.Close(fd)
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			f := os.NewFile(uintptr(fd), rel)
			dig, size, err := HashOpenedFile(f)
			_ = f.Close()
			if err != nil {
				return wrap(KindRead, "scanat", rel, err)
			}
			*entries = append(*entries, Entry{
				Rel:       rel,
				Type:      EntryFile,
				Size:      size,
				Mode:      uint32(mode.Perm()),
				Digest:    dig,
				HasDigest: true,
			})
		default:
			_ = unix.Close(fd)
			return unsupported("scanat", rel, "unsupported file type")
		}
	}
	return nil
}

func readDirNamesAt(dirfd int) ([]string, error) {
	dup, err := unix.Dup(dirfd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), ".")
	defer f.Close()
	if _, err := f.Seek(0, 0); err != nil {
		// Some platforms ignore seek on directories; continue.
		_ = err
	}
	return f.Readdirnames(-1)
}

func fileModeFromStat(mode uint32) os.FileMode {
	// Match os.FileMode conversion for permission bits and type bits we need.
	m := os.FileMode(mode & 0777)
	switch mode & unix.S_IFMT {
	case unix.S_IFDIR:
		m |= os.ModeDir
	case unix.S_IFLNK:
		m |= os.ModeSymlink
	case unix.S_IFIFO:
		m |= os.ModeNamedPipe
	case unix.S_IFSOCK:
		m |= os.ModeSocket
	case unix.S_IFBLK:
		m |= os.ModeDevice
	case unix.S_IFCHR:
		m |= os.ModeDevice | os.ModeCharDevice
	}
	return m
}
