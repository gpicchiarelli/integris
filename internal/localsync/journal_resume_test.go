package localsync_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/localsync"
)

func TestJournalResumeAfterInterrupt(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "aaa")
	mustWrite(t, filepath.Join(src, "b.txt"), "bbb")

	hooks := &localsync.ApplyHooks{
		BeforeRename: func(tmp, final string) error {
			if strings.HasSuffix(final, "b.txt") {
				return errors.New("injected crash before b.txt rename")
			}
			return nil
		},
	}
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst, Hooks: hooks})
	if err == nil {
		t.Fatal("expected interrupt")
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "aaa")
	if _, err := os.Lstat(filepath.Join(dst, "b.txt")); !os.IsNotExist(err) {
		t.Fatal("b.txt must not exist yet")
	}
	jpath := filepath.Join(dst, localsync.MetaDirName, localsync.JournalFileName)
	if _, err := os.Lstat(jpath); err != nil {
		t.Fatalf("journal missing: %v", err)
	}

	res, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Resumed {
		t.Fatalf("expected resumed: %+v", res)
	}
	assertFile(t, filepath.Join(dst, "b.txt"), "bbb")
	if res.Outcome != localsync.OutcomeSuccess {
		t.Fatalf("outcome=%s", res.Outcome)
	}

	// Confirm journal ends with confirmation.
	seg, err := journal.OpenFileSegment(jpath)
	if err != nil {
		t.Fatal(err)
	}
	defer seg.Close()
	prefix, err := journal.ReadPrefix(seg)
	if err != nil {
		t.Fatal(err)
	}
	if len(prefix.Records) == 0 || prefix.Records[len(prefix.Records)-1].Type != codec.TypeConfirmation {
		t.Fatalf("last record not confirmation: %+v", prefix.Records)
	}
}

func TestJournalIdempotentRerun(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "x")
	if _, err := localsync.Sync(localsync.Options{Source: src, Destination: dst}); err != nil {
		t.Fatal(err)
	}
	res2, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Resumed {
		t.Fatal("confirmed rerun should not resume incomplete txn")
	}
	if res2.Outcome != localsync.OutcomeSuccess {
		t.Fatalf("outcome=%s", res2.Outcome)
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "x")
}

func TestMetaDirNotSyncedAsContent(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "z")
	if _, err := localsync.Sync(localsync.Options{Source: src, Destination: dst}); err != nil {
		t.Fatal(err)
	}
	// Put a decoy under source .integris — scan must skip it.
	if err := os.MkdirAll(filepath.Join(src, localsync.MetaDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(src, localsync.MetaDirName, "secret"), "nope")
	res, err := localsync.Sync(localsync.Options{Source: src, Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dst, localsync.MetaDirName, "secret")); !os.IsNotExist(err) {
		t.Fatal("meta content must not sync")
	}
	_ = res
}

func TestDisableJournalStillWorks(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "y")
	_, err := localsync.Sync(localsync.Options{Source: src, Destination: dst, DisableJournal: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dst, localsync.MetaDirName)); !os.IsNotExist(err) {
		t.Fatal("journal meta should be absent when disabled")
	}
}
