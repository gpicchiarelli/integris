//go:build unix

package localsync

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/platform"
	"golang.org/x/sys/unix"
)

// ApplyAt publishes plan from sourceFD to destFD via openat (M3g).
// FDs are borrowed (not closed). Roots labels must match plan roots.
func ApplyAt(srcFD, dstFD *os.File, roots Roots, plan Plan, hooks *ApplyHooks) (ApplyResult, error) {
	return ApplyWithAt(srcFD, dstFD, roots, plan, ApplyOptions{Hooks: hooks})
}

// ApplyWithAt is ApplyWith using openat relative to conferred directory FDs.
func ApplyWithAt(srcFD, dstFD *os.File, roots Roots, plan Plan, opts ApplyOptions) (ApplyResult, error) {
	var out ApplyResult
	if srcFD == nil || dstFD == nil {
		return out, invalidArg("applyat", "nil source or destination fd")
	}
	if plan.SourceRoot != "" && plan.SourceRoot != roots.Source {
		return out, invalidArg("applyat", "plan source_root does not match roots")
	}
	if plan.DestRoot != "" && plan.DestRoot != roots.Destination {
		return out, invalidArg("applyat", "plan destination_root does not match roots")
	}
	if opts.StartAt < 0 || opts.StartAt > len(plan.Ops) {
		return out, invalidArg("applyat", "StartAt out of range")
	}

	srcDir := int(srcFD.Fd())
	dstDir := int(dstFD.Fd())

	if opts.CountPrior {
		for i := 0; i < opts.StartAt; i++ {
			switch plan.Ops[i].Action {
			case ActionSkip:
				out.Skipped++
			default:
				out.Completed++
			}
		}
	}
	out.Bytes = opts.InitialBytes
	bytesCum := out.Bytes
	for i := opts.StartAt; i < len(plan.Ops); i++ {
		op := plan.Ops[i]
		if err := validateRel(op.Rel); err != nil {
			out.Errors = append(out.Errors, err)
			return out, err
		}
		switch op.Action {
		case ActionSkip:
			out.Skipped++
		case ActionMkdir:
			if err := applyMkdirAt(dstDir, op); err != nil {
				out.Errors = append(out.Errors, err)
				return out, err
			}
			out.Completed++
		case ActionCopy, ActionReplace:
			n, err := applyFileAt(srcDir, dstDir, op, opts.Hooks)
			if err != nil {
				out.Errors = append(out.Errors, err)
				return out, err
			}
			out.Bytes += n
			bytesCum += n
			out.Completed++
		default:
			err := unsupported("applyat", op.Rel, "unknown action")
			out.Errors = append(out.Errors, err)
			return out, err
		}
		if opts.OnOpComplete != nil {
			if err := opts.OnOpComplete(i, op, bytesCum); err != nil {
				out.Errors = append(out.Errors, err)
				return out, err
			}
		}
	}
	return out, nil
}

func applyMkdirAt(dstDir int, op Op) error {
	mode := uint32(op.ExpectedMode)
	if mode == 0 {
		mode = 0o755
	}
	if st, err := fstatatPath(dstDir, op.Rel); err == nil {
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return unsupported("mkdir", op.Rel, "destination is a symbolic link")
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return classify(KindConflict, "mkdir", op.Rel, "destination exists and is not a directory", nil)
		}
		return nil
	} else if !errors.Is(err, unix.ENOENT) && !errors.Is(err, os.ErrNotExist) {
		return wrap(KindWrite, "mkdir", op.Rel, err)
	}
	fd, err := mkdiratAll(dstDir, op.Rel, mode)
	if err != nil {
		return mapWriteErr("mkdir", op.Rel, err)
	}
	_ = unix.Close(fd)
	if parent := filepath.ToSlash(filepath.Dir(op.Rel)); parent != "." && parent != "" {
		if pfd, err := openDirAt(dstDir, parent); err == nil {
			_ = unix.Fsync(pfd)
			_ = unix.Close(pfd)
		}
	} else {
		_ = unix.Fsync(dstDir)
	}
	return nil
}

func applyFileAt(srcDir, dstDir int, op Op, hooks *ApplyHooks) (int64, error) {
	want, err := digestFromHex(op.ExpectedDigestHex)
	if err != nil {
		return 0, wrap(KindInvalidArgument, "apply", op.Rel, err)
	}

	got, size, err := hashAt(srcDir, op.Rel)
	if err != nil {
		return 0, wrap(KindRead, "apply", op.Rel, err)
	}
	if got != want || (op.ExpectedSize != 0 && size != op.ExpectedSize) {
		return 0, classify(KindConflict, "apply", op.Rel, "source changed between plan and apply", nil)
	}

	parent := filepath.ToSlash(filepath.Dir(op.Rel))
	base := filepath.Base(op.Rel)
	if parent != "." && parent != "" {
		pfd, err := mkdiratAll(dstDir, parent, 0o755)
		if err != nil {
			return 0, mapWriteErr("apply", op.Rel, err)
		}
		_ = unix.Close(pfd)
	}

	if st, err := fstatatPath(dstDir, op.Rel); err == nil {
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return 0, unsupported("apply", op.Rel, "destination is a symbolic link")
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			return 0, classify(KindConflict, "apply", op.Rel, "destination is a directory", nil)
		}
	} else if !errors.Is(err, unix.ENOENT) && !errors.Is(err, os.ErrNotExist) {
		return 0, wrap(KindRead, "apply", op.Rel, err)
	}

	parentFD := dstDir
	var closeParent bool
	if parent != "." && parent != "" {
		var err error
		parentFD, err = openDirAt(dstDir, parent)
		if err != nil {
			return 0, mapWriteErr("apply", op.Rel, err)
		}
		closeParent = true
	}
	if closeParent {
		defer unix.Close(parentFD)
	}

	_ = cleanupTempsAt(parentFD)

	tmpName, err := createTempAt(parentFD)
	if err != nil {
		return 0, mapWriteErr("apply", op.Rel, err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(parentFD, tmpName, 0)
		}
	}()

	src, err := openatRead(srcDir, op.Rel)
	if err != nil {
		return 0, wrap(KindRead, "apply", op.Rel, err)
	}
	defer src.Close()

	tmpFD, err := unix.Openat(parentFD, tmpName, unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, mapWriteErr("apply", op.Rel, err)
	}
	tmp := os.NewFile(uintptr(tmpFD), tmpName)

	written, copyErr := io.Copy(tmp, src)
	syncErr := platform.SyncFile(tmp)
	closeErr := tmp.Close()
	if copyErr != nil {
		return 0, mapWriteErr("apply", op.Rel, copyErr)
	}
	if syncErr != nil {
		return 0, wrap(KindWrite, "apply", op.Rel, syncErr)
	}
	if closeErr != nil {
		return 0, wrap(KindWrite, "apply", op.Rel, closeErr)
	}

	if hooks != nil && hooks.AfterTempSync != nil {
		// Hooks remain path-oriented; CapEnter tests leave them nil.
		tmpPath := filepath.Join(".", tmpName)
		if err := hooks.AfterTempSync(tmpPath); err != nil {
			return 0, err
		}
	}

	tmpDig, _, err := hashAtName(parentFD, tmpName)
	if err != nil {
		return 0, wrap(KindVerify, "apply", op.Rel, err)
	}
	if tmpDig != want {
		return 0, classify(KindVerify, "apply", op.Rel, "staged content digest mismatch", nil)
	}

	mode := uint32(op.ExpectedMode)
	if mode == 0 {
		mode = 0o644
	}
	if err := unix.Fchmodat(parentFD, tmpName, mode, 0); err != nil {
		return 0, wrap(KindWrite, "apply", op.Rel, err)
	}

	if hooks != nil && hooks.BeforeRename != nil {
		if err := hooks.BeforeRename(tmpName, base); err != nil {
			return 0, err
		}
	}

	if err := unix.Renameat(parentFD, tmpName, parentFD, base); err != nil {
		return 0, mapWriteErr("apply", op.Rel, err)
	}
	cleanup = false
	_ = unix.Fsync(parentFD)

	finalDig, _, err := hashAtName(parentFD, base)
	if err != nil {
		return 0, wrap(KindVerify, "apply", op.Rel, err)
	}
	if finalDig != want {
		return 0, classify(KindVerify, "apply", op.Rel, "published content digest mismatch", nil)
	}
	return written, nil
}

func createTempAt(dirfd int) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	name := tmpPrefix + hex.EncodeToString(b[:]) + tmpSuffix
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	_ = unix.Close(fd)
	return name, nil
}

func cleanupTempsAt(dirfd int) error {
	names, err := readDirNamesAt(dirfd)
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.HasPrefix(name, tmpPrefix) && strings.HasSuffix(name, tmpSuffix) {
			_ = unix.Unlinkat(dirfd, name, 0)
		}
	}
	return nil
}

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

func openDirAt(dirfd int, rel string) (int, error) {
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

func openatRead(dirfd int, rel string) (*os.File, error) {
	rel = filepath.ToSlash(rel)
	parent := filepath.Dir(rel)
	base := filepath.Base(rel)
	pfd := dirfd
	var closeParent bool
	if parent != "." && parent != "" {
		var err error
		pfd, err = openDirAt(dirfd, parent)
		if err != nil {
			return nil, err
		}
		closeParent = true
	}
	fd, err := unix.Openat(pfd, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if closeParent {
		_ = unix.Close(pfd)
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), rel), nil
}

func hashAt(dirfd int, rel string) (codec.Digest, int64, error) {
	f, err := openatRead(dirfd, rel)
	if err != nil {
		return codec.Digest{}, 0, err
	}
	defer f.Close()
	return HashOpenedFile(f)
}

func hashAtName(dirfd int, name string) (codec.Digest, int64, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return codec.Digest{}, 0, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return HashOpenedFile(f)
}

func fstatatPath(dirfd int, rel string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstatat(dirfd, filepath.ToSlash(rel), &st, unix.AT_SYMLINK_NOFOLLOW)
	return st, err
}
