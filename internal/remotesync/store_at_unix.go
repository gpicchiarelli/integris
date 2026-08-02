//go:build unix

package remotesync

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/localsync"
	"github.com/gpicchiarelli/integris/internal/path"
	"github.com/gpicchiarelli/integris/internal/platform"
	"golang.org/x/sys/unix"
)

func openLocalStoreAt(destination string, destFD *os.File) (*localStore, error) {
	if destFD == nil {
		return openLocalStoreAmbient(destination)
	}
	stagePath := recvStageDir(destination)
	partialPath := recvPartialDir(destination)
	stageFD, partialFD, err := ensureRecvStageAt(int(destFD.Fd()))
	if err != nil {
		return nil, err
	}
	return &localStore{
		dest:      destination,
		stage:     stagePath,
		partial:   partialPath,
		destFD:    destFD,
		stageFD:   stageFD,
		partialFD: partialFD,
	}, nil
}

func ensureRecvStageAt(destFD int) (stageFD, partialFD int, err error) {
	if err := mkdiratOne(destFD, localsync.MetaDirName, 0o700); err != nil {
		return -1, -1, wrap(KindApply, "recv-meta", err)
	}
	metaFD, err := unix.Openat(destFD, localsync.MetaDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, -1, wrap(KindApply, "recv-meta open", err)
	}
	defer unix.Close(metaFD)
	if err := mkdiratOne(metaFD, "recv-stage", 0o700); err != nil {
		return -1, -1, wrap(KindApply, "recv-stage", err)
	}
	if err := mkdiratOne(metaFD, "recv-partial", 0o700); err != nil {
		return -1, -1, wrap(KindApply, "recv-partial", err)
	}
	stageFD, err = unix.Openat(metaFD, "recv-stage", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, -1, wrap(KindApply, "recv-stage open", err)
	}
	partialFD, err = unix.Openat(metaFD, "recv-partial", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		_ = unix.Close(stageFD)
		return -1, -1, wrap(KindApply, "recv-partial open", err)
	}
	return stageFD, partialFD, nil
}

func mkdiratOne(dirfd int, name string, perm uint32) error {
	if err := unix.Mkdirat(dirfd, name, perm); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

// mkdiratAll creates slash-separated rel under dirfd; returns an open FD for the
// final directory (caller must Close). rel "" returns Dup(dirfd).
func mkdiratAll(dirfd int, rel string, perm uint32) (int, error) {
	rel = filepath.ToSlash(rel)
	if rel == "" || rel == "." {
		return unix.Dup(dirfd)
	}
	cur, err := unix.Dup(dirfd)
	if err != nil {
		return -1, err
	}
	for _, comp := range strings.Split(rel, "/") {
		if comp == "" || comp == "." {
			continue
		}
		if comp == ".." {
			_ = unix.Close(cur)
			return -1, pathUnsafe("mkdirat", "path escapes root")
		}
		if comp == "" || strings.Contains(comp, "\\") || strings.Contains(comp, string(rune(0))) {
			_ = unix.Close(cur)
			return -1, pathUnsafe("mkdirat", "invalid component")
		}
		if _, err := path.ValidateJoined(comp, path.DefaultProfile); err != nil {
			_ = unix.Close(cur)
			return -1, wrap(KindApply, "mkdirat "+comp, err)
		}
		if err := mkdiratOne(cur, comp, perm); err != nil {
			_ = unix.Close(cur)
			return -1, err
		}
		next, err := unix.Openat(cur, comp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(cur)
		if err != nil {
			return -1, err
		}
		cur = next
	}
	return cur, nil
}

func (s *localStore) prepareDirsAt(entries []localsync.Entry) error {
	for _, e := range entries {
		if e.Type != localsync.EntryDir {
			continue
		}
		mode := uint32(e.Mode)
		if mode == 0 {
			mode = 0o755
		}
		fd, err := mkdiratAll(s.stageFD, e.Rel, mode)
		if err != nil {
			return wrap(KindApply, "mkdir", err)
		}
		_ = unix.Close(fd)
	}
	return nil
}

func (s *localStore) stageLegacyAt(fw fileWire) error {
	mode := uint32(fw.Mode)
	if mode == 0 {
		mode = 0o644
	}
	parent := filepath.ToSlash(filepath.Dir(fw.Rel))
	base := filepath.Base(fw.Rel)
	pfd := s.stageFD
	var closeParent bool
	if parent != "." && parent != "" {
		var err error
		pfd, err = mkdiratAll(s.stageFD, parent, 0o755)
		if err != nil {
			return wrap(KindApply, "mkdir parent", err)
		}
		closeParent = true
	}
	fd, err := unix.Openat(pfd, base, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if closeParent {
		_ = unix.Close(pfd)
	}
	if err != nil {
		return wrap(KindApply, "write", err)
	}
	f := os.NewFile(uintptr(fd), fw.Rel)
	_, werr := f.Write(fw.Data)
	cerr := f.Close()
	if werr != nil {
		return wrap(KindApply, "write", werr)
	}
	if cerr != nil {
		return wrap(KindApply, "write", cerr)
	}
	dig, _, err := hashAt(s.stageFD, fw.Rel)
	if err != nil || dig != fw.Digest {
		return failf(KindApply, "staged digest mismatch for %s", fw.Rel)
	}
	return nil
}

func (s *localStore) beginFileAt(begin fileBegin) (uint64, error) {
	if s.active {
		return 0, fail(KindProtocol, "file already active")
	}
	s.lastBegin = begin
	if st, err := fstatatRegular(s.stageFD, begin.Rel); err == nil && st.Size == int64(begin.Size) {
		dig, _, err := hashAt(s.stageFD, begin.Rel)
		if err == nil && dig == begin.Digest {
			clearPartialAt(s.partialFD, begin.Rel)
			return begin.Size, nil
		}
	}

	var start uint64
	meta, ok, err := loadPartialMetaAt(s.partialFD, begin.Rel)
	if err != nil {
		return 0, err
	}
	partRel := begin.Rel + ".part"
	if ok && meta.Digest == begin.Digest && meta.Size == int64(begin.Size) && meta.Rel == begin.Rel {
		if st, err := fstatatRegular(s.partialFD, partRel); err == nil && st.Size == meta.Offset {
			start = uint64(meta.Offset)
		} else {
			clearPartialAt(s.partialFD, begin.Rel)
			start = 0
		}
	} else {
		clearPartialAt(s.partialFD, begin.Rel)
		start = 0
	}

	flags := unix.O_RDWR | unix.O_CREAT | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if start == 0 {
		flags |= unix.O_TRUNC
	}
	pf, err := openatCreate(s.partialFD, partRel, flags, 0o600)
	if err != nil {
		return 0, wrap(KindApply, "partial open", err)
	}
	if start > 0 {
		if _, err := pf.Seek(int64(start), io.SeekStart); err != nil {
			_ = pf.Close()
			return 0, wrap(KindApply, "partial seek", err)
		}
	}
	s.active = true
	s.begin = begin
	s.partPath = partRel // relative label under partialFD
	s.pf = pf
	s.off = start
	return start, nil
}

func (s *localStore) persistActiveAt() {
	if !s.active || s.pf == nil {
		return
	}
	_ = writePartialMetaAt(s.partialFD, s.begin.Rel, partialMeta{
		Rel: s.begin.Rel, Mode: s.begin.Mode, Size: int64(s.begin.Size),
		Digest: s.begin.Digest, Offset: int64(s.off),
	})
	_ = platform.SyncFile(s.pf)
}

func (s *localStore) endFileAt(rel string, dig codec.Digest) error {
	if !s.active || s.pf == nil {
		return fail(KindProtocol, "end without begin")
	}
	if rel != s.begin.Rel || dig != s.begin.Digest {
		return fail(KindProtocol, "file end mismatch")
	}
	if s.off != s.begin.Size {
		return fail(KindProtocol, "unexpected file end before size complete")
	}
	if err := platform.SyncFile(s.pf); err != nil {
		return wrap(KindApply, "partial sync", err)
	}
	if err := s.pf.Close(); err != nil {
		return wrap(KindApply, "partial close", err)
	}
	s.pf = nil

	got, _, err := hashAt(s.partialFD, s.partPath)
	if err != nil || got != s.begin.Digest {
		return failf(KindApply, "chunked digest mismatch for %s", s.begin.Rel)
	}

	mode := uint32(s.begin.Mode)
	if mode == 0 {
		mode = 0o644
	}
	parent := filepath.ToSlash(filepath.Dir(s.begin.Rel))
	if parent != "." && parent != "" {
		pfd, err := mkdiratAll(s.stageFD, parent, 0o755)
		if err != nil {
			return wrap(KindApply, "final mkdir", err)
		}
		_ = unix.Close(pfd)
	}
	// Prefer renameat with nested relative paths.
	if err := unix.Renameat(s.partialFD, s.partPath, s.stageFD, s.begin.Rel); err != nil {
		// Fallback: copy via openat.
		src, err := openatRead(s.partialFD, s.partPath)
		if err != nil {
			return wrap(KindApply, "finalize read", err)
		}
		data, err := io.ReadAll(src)
		_ = src.Close()
		if err != nil {
			return wrap(KindApply, "finalize read", err)
		}
		dst, err := openatCreate(s.stageFD, s.begin.Rel, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
		if err != nil {
			return wrap(KindApply, "finalize write", err)
		}
		_, werr := dst.Write(data)
		cerr := dst.Close()
		if werr != nil {
			return wrap(KindApply, "finalize write", werr)
		}
		if cerr != nil {
			return wrap(KindApply, "finalize write", cerr)
		}
		_ = unlinkatPath(s.partialFD, s.partPath)
	} else {
		_ = fchmodatPath(s.stageFD, s.begin.Rel, mode)
	}
	clearPartialAt(s.partialFD, s.begin.Rel)
	_ = unix.Fsync(s.stageFD)
	s.active = false
	s.partPath = ""
	return nil
}

func (s *localStore) closeAt() {
	if s.stageFD >= 0 {
		_ = unix.Close(s.stageFD)
		s.stageFD = -1
	}
	if s.partialFD >= 0 {
		_ = unix.Close(s.partialFD)
		s.partialFD = -1
	}
}

// resetStageAt clears recv-stage/recv-partial via unlinkat and reopens dirfds (M3g).
func (s *localStore) resetStageAt() error {
	if s.destFD == nil {
		return fail(KindApply, "resetStageAt without dest FD")
	}
	if s.stageFD >= 0 {
		_ = clearDirContentsAt(s.stageFD)
	}
	if s.partialFD >= 0 {
		_ = clearDirContentsAt(s.partialFD)
	}
	s.closeAt()
	stageFD, partialFD, err := ensureRecvStageAt(int(s.destFD.Fd()))
	if err != nil {
		return err
	}
	s.stageFD = stageFD
	s.partialFD = partialFD
	return nil
}

func clearDirContentsAt(dirfd int) error {
	names, err := readDirNamesAt(dirfd)
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == "." || name == ".." {
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			sub, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				continue
			}
			_ = clearDirContentsAt(sub)
			_ = unix.Close(sub)
			_ = unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
			continue
		}
		_ = unix.Unlinkat(dirfd, name, 0)
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
	return f.Readdirnames(-1)
}

func openatCreate(dirfd int, rel string, flags int, mode uint32) (*os.File, error) {
	rel = filepath.ToSlash(rel)
	parent := filepath.Dir(rel)
	base := filepath.Base(rel)
	pfd := dirfd
	var closeParent bool
	if parent != "." && parent != "" {
		var err error
		pfd, err = mkdiratAll(dirfd, parent, 0o700)
		if err != nil {
			return nil, err
		}
		closeParent = true
	}
	fd, err := unix.Openat(pfd, base, flags, mode)
	if closeParent {
		_ = unix.Close(pfd)
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), rel), nil
}

func openatRead(dirfd int, rel string) (*os.File, error) {
	return openatCreate(dirfd, rel, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

func hashAt(dirfd int, rel string) (codec.Digest, int64, error) {
	f, err := openatRead(dirfd, rel)
	if err != nil {
		return codec.Digest{}, 0, err
	}
	defer f.Close()
	return localsync.HashOpenedFile(f)
}

func fstatatRegular(dirfd int, rel string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstatat(dirfd, filepath.ToSlash(rel), &st, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return st, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return st, os.ErrNotExist
	}
	return st, nil
}

func writePartialMetaAt(partialFD int, rel string, m partialMeta) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	metaRel := rel + ".meta.json"
	tmpRel := metaRel + ".tmp"
	f, err := openatCreate(partialFD, tmpRel, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(raw)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	if err := unix.Renameat(partialFD, tmpRel, partialFD, metaRel); err != nil {
		_ = unlinkatPath(partialFD, tmpRel)
		return err
	}
	return nil
}

func loadPartialMetaAt(partialFD int, rel string) (partialMeta, bool, error) {
	var zero partialMeta
	f, err := openatRead(partialFD, rel+".meta.json")
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			return zero, false, nil
		}
		return zero, false, err
	}
	raw, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return zero, false, err
	}
	if err := json.Unmarshal(raw, &zero); err != nil {
		return partialMeta{}, false, err
	}
	return zero, true, nil
}

func clearPartialAt(partialFD int, rel string) {
	_ = unlinkatPath(partialFD, rel+".meta.json")
	_ = unlinkatPath(partialFD, rel+".part")
}

func unlinkatPath(dirfd int, rel string) error {
	rel = filepath.ToSlash(rel)
	parent := filepath.Dir(rel)
	base := filepath.Base(rel)
	if parent == "." || parent == "" {
		return unix.Unlinkat(dirfd, base, 0)
	}
	pfd, err := openDirAt(dirfd, parent)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	return unix.Unlinkat(pfd, base, 0)
}

func openDirAt(dirfd int, rel string) (int, error) {
	rel = filepath.ToSlash(rel)
	cur, err := unix.Dup(dirfd)
	if err != nil {
		return -1, err
	}
	for _, comp := range strings.Split(rel, "/") {
		if comp == "" || comp == "." {
			continue
		}
		if comp == ".." {
			_ = unix.Close(cur)
			return -1, unix.EPERM
		}
		next, err := unix.Openat(cur, comp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(cur)
		if err != nil {
			return -1, err
		}
		cur = next
	}
	return cur, nil
}

func fchmodatPath(dirfd int, rel string, mode uint32) error {
	rel = filepath.ToSlash(rel)
	parent := filepath.Dir(rel)
	base := filepath.Base(rel)
	if parent == "." || parent == "" {
		return unix.Fchmodat(dirfd, base, mode, 0)
	}
	pfd, err := openDirAt(dirfd, parent)
	if err != nil {
		return err
	}
	defer unix.Close(pfd)
	return unix.Fchmodat(pfd, base, mode, 0)
}

func pathUnsafe(op, msg string) error {
	return failf(KindApply, "%s: %s", op, msg)
}
