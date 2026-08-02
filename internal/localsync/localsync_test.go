package localsync_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gpicchiarelli/integris/internal/localsync"
)

func TestEmptySource(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	res, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != localsync.OutcomeSuccess || res.PlannedOps != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSingleFileAndNested(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "world")
	res, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	if res.CompletedOps < 2 {
		t.Fatalf("expected copies, got %+v", res)
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "world")
}

func TestIdenticalSkip(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "same")
	mustWrite(t, filepath.Join(dst, "a.txt"), "same")
	res, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	if res.SkippedOps != 1 || res.CompletedOps != 0 {
		t.Fatalf("expected skip: %+v", res)
	}
}

func TestSameSizeDifferentContent(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "aaaa")
	mustWrite(t, filepath.Join(dst, "a.txt"), "bbbb")
	res, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "aaaa")
	if !hasAction(res.Plan, localsync.ActionReplace) {
		t.Fatalf("expected replace: %+v", res.Plan)
	}
}

func TestReplaceExisting(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "new")
	mustWrite(t, filepath.Join(dst, "a.txt"), "old")
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "new")
}

func TestReadError(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	p := filepath.Join(src, "a.txt")
	mustWrite(t, p, "x")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err == nil {
		t.Fatal("expected read error")
	}
	if !localsync.IsKind(err, localsync.KindRead) && !localsync.IsKind(err, localsync.KindPermission) {
		t.Fatalf("kind=%v err=%v", err, err)
	}
}

func TestWriteError(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "data")
	if err := os.Chmod(dst, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dst, 0o755) })
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err == nil {
		t.Fatal("expected write error")
	}
	if !localsync.IsKind(err, localsync.KindWrite) && !localsync.IsKind(err, localsync.KindPermission) {
		t.Fatalf("unexpected kind: %v", err)
	}
}

func TestMissingDestination(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "nested", "out")
	mustWrite(t, filepath.Join(src, "a.txt"), "z")
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "z")
}

func TestSamePathRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := localsync.Sync(localsync.Options{Source: dir, Destination: dir})
	if !localsync.IsKind(err, localsync.KindPathUnsafe) {
		t.Fatalf("got %v", err)
	}
}

func TestDestinationInsideSource(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(src, "out")
	if err := os.Mkdir(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if !localsync.IsKind(err, localsync.KindPathUnsafe) {
		t.Fatalf("got %v", err)
	}
}

func TestSourceInsideDestination(t *testing.T) {
	dst := t.TempDir()
	src := filepath.Join(dst, "in")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if !localsync.IsKind(err, localsync.KindPathUnsafe) {
		t.Fatalf("got %v", err)
	}
}

func TestDotDotRejectedInTree(t *testing.T) {
	// Grammar rejects ".." components; craft via ValidateJoined.
	_, err := localsync.ParsePlanJSON([]byte(`{"ops":[{"action":"copy","rel":"a/../b","reason":"missing","initial":"absent","final":"file"}]}`))
	if err != nil {
		// parse succeeds; apply must reject
	}
	roots := localsync.Roots{Source: t.TempDir(), Destination: t.TempDir()}
	plan := localsync.Plan{Ops: []localsync.Op{{
		Action: localsync.ActionCopy, Rel: "a/../b", ExpectedDigestHex: strings.Repeat("00", 32),
	}}}
	_, err = localsync.Apply(roots, plan, nil)
	if !localsync.IsKind(err, localsync.KindPathUnsafe) {
		t.Fatalf("got %v", err)
	}
}

func TestSymlinkInSource(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	target := filepath.Join(src, "t.txt")
	mustWrite(t, target, "x")
	if err := os.Symlink(target, filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if !localsync.IsKind(err, localsync.KindUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestResidualTempCleanup(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "data")
	orphan := filepath.Join(dst, ".integris.deadbeefdeadbeef.tmp")
	mustWrite(t, orphan, "junk")
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan temp not cleaned: %v", err)
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "data")
}

func TestInterruptBeforeRename(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "payload")
	hooks := &localsync.ApplyHooks{
		BeforeRename: func(tmp, final string) error {
			return errors.New("injected interrupt")
		},
	}
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst, Hooks: hooks})
	if err == nil {
		t.Fatal("expected interrupt")
	}
	if _, err := os.Lstat(filepath.Join(dst, "a.txt")); !os.IsNotExist(err) {
		t.Fatal("final file must not exist after interrupt")
	}
}

func TestVerifyFailure(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "payload")
	hooks := &localsync.ApplyHooks{
		AfterTempSync: func(tmp string) error {
			return os.WriteFile(tmp, []byte("corrupted"), 0o600)
		},
	}
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst, Hooks: hooks})
	if !localsync.IsKind(err, localsync.KindVerify) {
		t.Fatalf("got %v", err)
	}
}

func TestPlanDeterministicOrder(t *testing.T) {
	src := t.TempDir()
	mustWrite(t, filepath.Join(src, "c.txt"), "c")
	mustWrite(t, filepath.Join(src, "a.txt"), "a")
	mustWrite(t, filepath.Join(src, "b", "x.txt"), "x")
	srcMan, err := localsync.Scan(src)
	if err != nil {
		t.Fatal(err)
	}
	dstMan := localsync.Manifest{Root: t.TempDir()}
	p1, err := localsync.BuildPlan(srcMan, dstMan)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := localsync.BuildPlan(srcMan, dstMan)
	if err != nil {
		t.Fatal(err)
	}
	j1, _ := p1.FormatJSON()
	j2, _ := p2.FormatJSON()
	if !bytes.Equal(j1, j2) {
		t.Fatalf("non-deterministic plan\n%s\n%s", j1, j2)
	}
	var prev string
	for _, op := range p1.Ops {
		if op.Rel < prev {
			t.Fatalf("ops not sorted: %q after %q", op.Rel, prev)
		}
		prev = op.Rel
	}
}

func TestUnicodeNFCName(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	name := "café.txt" // NFC
	mustWrite(t, filepath.Join(src, name), "u")
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(dst, name), "u")
}

func TestEmptyFile(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "e.txt"), "")
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(dst, "e.txt"), "")
}

func TestLargerFile(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	data := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	mustWrite(t, filepath.Join(src, "big.bin"), string(data))
	res, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesTransferred != int64(len(data)) {
		t.Fatalf("bytes=%d", res.BytesTransferred)
	}
	got, err := os.ReadFile(filepath.Join(dst, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content mismatch")
	}
}

func TestSourceChangedBetweenPlanAndApply(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "one")
	srcMan, err := localsync.Scan(src)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := localsync.BuildPlan(srcMan, localsync.Manifest{Root: dst})
	if err != nil {
		t.Fatal(err)
	}
	plan.SourceRoot = src
	plan.DestRoot = dst
	mustWrite(t, filepath.Join(src, "a.txt"), "two")
	roots := localsync.Roots{Source: src, Destination: dst}
	_, err = localsync.Apply(roots, plan, nil)
	if !localsync.IsKind(err, localsync.KindConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestNoWriteOutsideDestination(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	outside := t.TempDir()
	marker := filepath.Join(outside, "must-not-appear")
	mustWrite(t, filepath.Join(src, "a.txt"), "x")
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("outside marker created")
	}
	// Escape attempt via crafted plan.
	roots := localsync.Roots{Source: src, Destination: dst}
	evil := localsync.Plan{
		SourceRoot: src,
		DestRoot:   dst,
		Ops: []localsync.Op{{
			Action:            localsync.ActionCopy,
			Rel:               "../escape.txt",
			ExpectedDigestHex: strings.Repeat("ab", 32),
		}},
	}
	_, err = localsync.Apply(roots, evil, nil)
	if !localsync.IsKind(err, localsync.KindPathUnsafe) {
		t.Fatalf("got %v", err)
	}
}

func TestPlanJSONRoundTrip(t *testing.T) {
	src := t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "x")
	man, err := localsync.Scan(src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := localsync.BuildPlan(man, localsync.Manifest{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p.FormatJSON()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := localsync.ParsePlanJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := p2.FormatJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("roundtrip mismatch")
	}
	var check map[string]any
	if err := json.Unmarshal(raw, &check); err != nil {
		t.Fatal(err)
	}
}

func TestPlanOnlyNoWrites(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "x")
	res, err := localsync.Sync(localsync.Options{Source: src, Destination: dst, PlanOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "a.txt")); !os.IsNotExist(err) {
		t.Fatal("plan-only must not write")
	}
	if res.PlannedOps == 0 {
		t.Fatal("expected planned ops")
	}
}

func TestSourceNeverModified(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	p := filepath.Join(src, "a.txt")
	mustWrite(t, p, "keep")
	st1, _ := os.Stat(p)
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(p)
	if st1.ModTime() != st2.ModTime() || st1.Size() != st2.Size() {
		t.Fatal("source modified")
	}
	assertFile(t, p, "keep")
}

func TestResolveRootsAllowsMetaStaging(t *testing.T) {
	dst := t.TempDir()
	stage := filepath.Join(dst, localsync.MetaDirName, "recv-stage")
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(stage, "a.txt"), "staged")
	if _, err := localsync.ResolveRoots(stage, dst, false); err != nil {
		t.Fatalf("meta staging should be allowed: %v", err)
	}
	nested := filepath.Join(dst, "user-subdir")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := localsync.ResolveRoots(nested, dst, false); err == nil {
		t.Fatal("source inside destination outside .integris must fail")
	}
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != want {
		t.Fatalf("got %q want %q", b, want)
	}
}

func hasAction(p localsync.Plan, a localsync.Action) bool {
	for _, op := range p.Ops {
		if op.Action == a {
			return true
		}
	}
	return false
}
