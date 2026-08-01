//go:build unix

package path

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// OSFile is a Unix descriptor-backed File/Dir for platform resolution tests
// and future apply adapters. Opens use openat(2) with O_NOFOLLOW.
type OSFile struct {
	fd   int
	dir  bool
	info FileInfo
}

// OpenOSRoot opens path as a directory root and captures volume identity (st_dev).
func OpenOSRoot(path string) (*OSFile, RootIdentity, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, RootIdentity{}, fmt.Errorf("open root: %w", err)
	}
	f := &OSFile{fd: fd, dir: true}
	runtime.SetFinalizer(f, (*OSFile).finalize)
	info, err := f.stat()
	if err != nil {
		_ = f.Close()
		return nil, RootIdentity{}, err
	}
	if info.Type != TypeDir {
		_ = f.Close()
		return nil, RootIdentity{}, reject(RuleType, -1, "root is not a directory")
	}
	f.info = info
	return f, RootIdentity{Volume: info.Volume}, nil
}

func (f *OSFile) finalize() {
	if f != nil && f.fd >= 0 {
		_ = unix.Close(f.fd)
		f.fd = -1
	}
}

func (f *OSFile) Info() (FileInfo, error) {
	if f == nil || f.fd < 0 {
		return FileInfo{}, reject(RuleOpen, -1, "descriptor closed")
	}
	return f.stat()
}

func (f *OSFile) Close() error {
	if f == nil || f.fd < 0 {
		return nil
	}
	runtime.SetFinalizer(f, nil)
	err := unix.Close(f.fd)
	f.fd = -1
	return err
}

func (f *OSFile) OpenNoFollow(ctx context.Context, name []byte) (File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f == nil || f.fd < 0 || !f.dir {
		return nil, reject(RuleOpen, -1, "invalid directory descriptor")
	}
	if len(name) == 0 || len(name) > MaxComponentBytes {
		return nil, reject(RuleLen, -1, "component length")
	}
	// Single component only; reject embedded separators defensively.
	for _, c := range name {
		if c == '/' || c == '\\' || c == 0 {
			return nil, reject(RuleSep, -1, "invalid component byte")
		}
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NOCTTY
	fd, err := unix.Openat(f.fd, string(name), flags, 0)
	if err != nil {
		return nil, mapOpenErr(err)
	}
	child := &OSFile{fd: fd}
	runtime.SetFinalizer(child, (*OSFile).finalize)
	info, err := child.stat()
	if err != nil {
		_ = child.Close()
		return nil, err
	}
	child.info = info
	child.dir = info.Type == TypeDir
	if child.dir {
		return child, nil
	}
	return child, nil
}

func (f *OSFile) stat() (FileInfo, error) {
	var st unix.Stat_t
	if err := unix.Fstat(f.fd, &st); err != nil {
		return FileInfo{}, reject(RuleOpen, -1, "fstat: "+err.Error())
	}
	mode := st.Mode
	var typ ObjectType
	switch mode & unix.S_IFMT {
	case unix.S_IFDIR:
		typ = TypeDir
	case unix.S_IFREG:
		typ = TypeFile
	case unix.S_IFLNK:
		typ = TypeSymlink
	default:
		typ = TypeOther
	}
	nlink := uint32(st.Nlink)
	return FileInfo{
		Type:      typ,
		ID:        Identity(st.Ino),
		Volume:    VolumeID(st.Dev),
		LinkCount: nlink,
		Mode:      uint32(mode),
	}, nil
}

func mapOpenErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, syscall.ELOOP) {
		return reject(RuleLink, -1, "symlink or openat ELOOP")
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return reject(RuleOpen, -1, "not found")
	}
	return reject(RuleOpen, -1, err.Error())
}

var (
	_ File = (*OSFile)(nil)
	_ Dir  = (*OSFile)(nil)
)
