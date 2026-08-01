package journal_test

import (
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
)

func TestCrashSegmentJAppendCatalog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal")
	inner, err := journal.OpenFileSegment(path)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()

	cs := &journal.CrashSegment{Inner: inner, Dir: dir}
	w, _, err := journal.OpenWriter(cs)
	if err != nil {
		t.Fatal(err)
	}
	var id codec.TransactionID
	id[0] = 1
	if _, err := w.Append(id, codec.TypeObservation, []byte("seed")); err != nil {
		t.Fatal(err)
	}
	seedSize := cs.Size()

	cases := []struct {
		label string
		check func(t *testing.T, cs *journal.CrashSegment, appendErr error)
	}{
		{
			label: journal.CrashJAppendPre,
			check: func(t *testing.T, cs *journal.CrashSegment, appendErr error) {
				t.Helper()
				if !journal.IsInjectedCrash(appendErr) {
					t.Fatalf("want injected crash, got %v", appendErr)
				}
				if cs.Size() != seedSize {
					t.Fatalf("size=%d want %d", cs.Size(), seedSize)
				}
				p, err := journal.ReadPrefix(cs)
				if err != nil || p.Torn || len(p.Records) != 1 {
					t.Fatalf("prefix err=%v torn=%v n=%d", err, p.Torn, len(p.Records))
				}
			},
		},
		{
			label: journal.CrashJAppendMid,
			check: func(t *testing.T, cs *journal.CrashSegment, appendErr error) {
				t.Helper()
				if !journal.IsInjectedCrash(appendErr) {
					t.Fatalf("want injected crash, got %v", appendErr)
				}
				if cs.Size() <= seedSize {
					t.Fatalf("expected partial growth, size=%d seed=%d", cs.Size(), seedSize)
				}
				p, err := journal.ReadPrefix(cs)
				if err != nil || !p.Torn || len(p.Records) != 1 {
					t.Fatalf("prefix err=%v torn=%v n=%d", err, p.Torn, len(p.Records))
				}
			},
		},
		{
			label: journal.CrashJAppendPost,
			check: func(t *testing.T, cs *journal.CrashSegment, appendErr error) {
				t.Helper()
				if !journal.IsInjectedCrash(appendErr) {
					t.Fatalf("want injected crash, got %v", appendErr)
				}
				p, err := journal.ReadPrefix(cs)
				if err != nil || p.Torn || len(p.Records) != 2 {
					t.Fatalf("prefix err=%v torn=%v n=%d", err, p.Torn, len(p.Records))
				}
			},
		},
		{
			label: journal.CrashJMetaPost,
			check: func(t *testing.T, cs *journal.CrashSegment, appendErr error) {
				t.Helper()
				if !journal.IsInjectedCrash(appendErr) {
					t.Fatalf("want injected crash, got %v", appendErr)
				}
				p, err := journal.ReadPrefix(cs)
				if err != nil || p.Torn || len(p.Records) != 2 {
					t.Fatalf("prefix err=%v torn=%v n=%d", err, p.Torn, len(p.Records))
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			// Reset to seed-only durable prefix.
			if err := inner.Truncate(seedSize); err != nil {
				t.Fatal(err)
			}
			cs.FailAt = ""
			cs.Hits = nil
			w2, _, err := journal.OpenWriter(cs)
			if err != nil {
				t.Fatal(err)
			}
			cs.FailAt = tc.label
			_, err = w2.Append(id, codec.TypeProgress, []byte("crash-me"))
			tc.check(t, cs, err)
			if len(cs.Hits) != 1 || cs.Hits[0] != tc.label {
				t.Fatalf("hits=%v", cs.Hits)
			}
		})
	}
}
