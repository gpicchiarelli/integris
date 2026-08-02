package localsync

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gpicchiarelli/integris/internal/path"
	"github.com/gpicchiarelli/integris/internal/platform"
)

const (
	tmpPrefix = ".integris."
	tmpSuffix = ".tmp"
)

// ApplyHooks are optional test/fault-injection points. Production uses nil.
type ApplyHooks struct {
	// AfterTempSync is invoked after the temp file is written and synced, before
	// digest verification. Tests may corrupt the temp file here.
	AfterTempSync func(tmpPath string) error
	// BeforeRename is invoked after digest verification of the temp file and
	// before os.Rename to the final path. Returning an error aborts apply.
	BeforeRename func(tmpPath, finalPath string) error
}

// ApplyResult accumulates per-operation outcomes.
type ApplyResult struct {
	Completed int
	Skipped   int
	Bytes     int64
	Errors    []error
}

// ApplyOptions controls resumable apply.
type ApplyOptions struct {
	Hooks *ApplyHooks
	// StartAt is the first plan op index to execute (0-based). Prior ops are
	// treated as already durable (resume). Skipped/completed counters only
	// reflect ops executed in this call unless CountPrior is set.
	StartAt int
	// CountPrior adds StartAt prior ops into Completed/Skipped based on plan
	// actions (for result reporting after resume).
	CountPrior bool
	// InitialBytes seeds the transferred-byte counter (resume).
	InitialBytes int64
	// OnOpComplete is invoked after a successful op and before the next op.
	// A non-nil error aborts apply (journal append failure, etc.).
	OnOpComplete func(index int, op Op, bytesCum int64) error
}

// Apply executes plan against roots. Source is never modified. File publication
// uses temp-in-dir → write → sync → verify → chmod → rename → dirsync.
func Apply(roots Roots, plan Plan, hooks *ApplyHooks) (ApplyResult, error) {
	return ApplyWith(roots, plan, ApplyOptions{Hooks: hooks})
}

// ApplyWith executes plan with resume and journaling callbacks.
func ApplyWith(roots Roots, plan Plan, opts ApplyOptions) (ApplyResult, error) {
	var out ApplyResult
	if plan.SourceRoot != "" && plan.SourceRoot != roots.Source {
		return out, invalidArg("apply", "plan source_root does not match roots")
	}
	if plan.DestRoot != "" && plan.DestRoot != roots.Destination {
		return out, invalidArg("apply", "plan destination_root does not match roots")
	}
	if opts.StartAt < 0 || opts.StartAt > len(plan.Ops) {
		return out, invalidArg("apply", "StartAt out of range")
	}

	if err := os.MkdirAll(roots.Destination, 0o755); err != nil {
		return out, wrap(KindWrite, "apply", "", err)
	}

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
			if err := applyMkdir(roots.Destination, op); err != nil {
				out.Errors = append(out.Errors, err)
				return out, err
			}
			out.Completed++
		case ActionCopy, ActionReplace:
			n, err := applyFile(roots, op, opts.Hooks)
			if err != nil {
				out.Errors = append(out.Errors, err)
				return out, err
			}
			out.Bytes += n
			bytesCum += n
			out.Completed++
		default:
			err := unsupported("apply", op.Rel, "unknown action")
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

func validateRel(rel string) error {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return pathUnsafe("apply", "invalid relative path")
	}
	if _, err := path.ValidateJoined(rel, path.DefaultProfile); err != nil {
		return classify(KindPathUnsafe, "apply", rel, "logical path rejected", err)
	}
	return nil
}

func applyMkdir(dstRoot string, op Op) error {
	native := joinUnder(dstRoot, op.Rel)
	if native == "" {
		return pathUnsafe("mkdir", "escaped destination root")
	}
	mode := os.FileMode(op.ExpectedMode)
	if mode == 0 {
		mode = 0o755
	}
	fi, err := os.Lstat(native)
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return unsupported("mkdir", op.Rel, "destination is a symbolic link")
		}
		if !fi.IsDir() {
			return classify(KindConflict, "mkdir", op.Rel, "destination exists and is not a directory", nil)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return wrap(KindWrite, "mkdir", op.Rel, err)
	}
	if err := os.MkdirAll(native, mode); err != nil {
		return mapWriteErr("mkdir", op.Rel, err)
	}
	_ = platform.SyncDir(filepath.Dir(native))
	return nil
}

func applyFile(roots Roots, op Op, hooks *ApplyHooks) (int64, error) {
	want, err := digestFromHex(op.ExpectedDigestHex)
	if err != nil {
		return 0, wrap(KindInvalidArgument, "apply", op.Rel, err)
	}

	srcNative := joinUnder(roots.Source, op.Rel)
	dstNative := joinUnder(roots.Destination, op.Rel)
	if srcNative == "" || dstNative == "" {
		return 0, pathUnsafe("apply", "path escapes sync root")
	}

	// Re-validate source has not changed since planning (TOCTOU mitigation).
	got, size, err := HashFile(srcNative)
	if err != nil {
		return 0, wrap(KindRead, "apply", op.Rel, err)
	}
	if got != want || (op.ExpectedSize != 0 && size != op.ExpectedSize) {
		return 0, classify(KindConflict, "apply", op.Rel, "source changed between plan and apply", nil)
	}

	if err := os.MkdirAll(filepath.Dir(dstNative), 0o755); err != nil {
		return 0, mapWriteErr("apply", op.Rel, err)
	}

	// Refuse symlink at destination final path.
	if fi, err := os.Lstat(dstNative); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return 0, unsupported("apply", op.Rel, "destination is a symbolic link")
		}
		if fi.IsDir() {
			return 0, classify(KindConflict, "apply", op.Rel, "destination is a directory", nil)
		}
	} else if !os.IsNotExist(err) {
		return 0, wrap(KindRead, "apply", op.Rel, err)
	}

	_ = cleanupTemps(filepath.Dir(dstNative), filepath.Base(dstNative))

	tmpPath, err := createTemp(filepath.Dir(dstNative))
	if err != nil {
		return 0, mapWriteErr("apply", op.Rel, err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	src, err := openFileRead(srcNative)
	if err != nil {
		return 0, wrap(KindRead, "apply", op.Rel, err)
	}
	defer src.Close()

	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, mapWriteErr("apply", op.Rel, err)
	}

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
		if err := hooks.AfterTempSync(tmpPath); err != nil {
			return 0, err
		}
	}

	// Verify temp content before rename.
	tmpDig, _, err := HashFile(tmpPath)
	if err != nil {
		return 0, wrap(KindVerify, "apply", op.Rel, err)
	}
	if tmpDig != want {
		return 0, classify(KindVerify, "apply", op.Rel, "staged content digest mismatch", nil)
	}

	mode := os.FileMode(op.ExpectedMode)
	if mode == 0 {
		mode = 0o644
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return 0, wrap(KindWrite, "apply", op.Rel, err)
	}

	if hooks != nil && hooks.BeforeRename != nil {
		if err := hooks.BeforeRename(tmpPath, dstNative); err != nil {
			return 0, err
		}
	}

	if err := os.Rename(tmpPath, dstNative); err != nil {
		return 0, mapWriteErr("apply", op.Rel, err)
	}
	cleanup = false

	_ = platform.SyncDir(filepath.Dir(dstNative))

	// Final verification of published file.
	finalDig, _, err := HashFile(dstNative)
	if err != nil {
		return 0, wrap(KindVerify, "apply", op.Rel, err)
	}
	if finalDig != want {
		return 0, classify(KindVerify, "apply", op.Rel, "published content digest mismatch", nil)
	}
	return written, nil
}

func createTemp(dir string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	name := tmpPrefix + hex.EncodeToString(b[:]) + tmpSuffix
	p := filepath.Join(dir, name)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(p)
		return "", err
	}
	return p, nil
}

func cleanupTemps(dir, finalBase string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, tmpPrefix) && strings.HasSuffix(name, tmpSuffix) {
			_ = os.Remove(filepath.Join(dir, name))
		}
		_ = finalBase
	}
	return nil
}

// joinUnder joins root and slash-separated rel, rejecting escapes.
func joinUnder(root, rel string) string {
	if err := validateRel(rel); err != nil {
		return ""
	}
	parts := strings.Split(rel, "/")
	native := root
	for _, p := range parts {
		native = filepath.Join(native, p)
	}
	cleanRoot := filepath.Clean(root)
	cleanNative := filepath.Clean(native)
	relOut, err := filepath.Rel(cleanRoot, cleanNative)
	if err != nil || relOut == ".." || strings.HasPrefix(relOut, ".."+string(filepath.Separator)) {
		return ""
	}
	return cleanNative
}

func mapWriteErr(op, rel string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrPermission) {
		return wrap(KindPermission, op, rel, err)
	}
	// ENOSPC / EDQUOT — best-effort via string-free syscall errno on unix
	if isNoSpace(err) {
		return wrap(KindNoSpace, op, rel, err)
	}
	return wrap(KindWrite, op, rel, err)
}
