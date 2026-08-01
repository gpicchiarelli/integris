package recovery_test

import (
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

func seedAuthFileJournal(t *testing.T, cs *journal.CrashSegment) codec.TransactionID {
	t.Helper()
	w, _, err := journal.OpenWriter(cs)
	if err != nil {
		t.Fatal(err)
	}
	id := txid(3)
	b := binding()
	appendRec(t, w, id, codec.TypePlanDigest, b.PlanDigest[:])
	appendRec(t, w, id, codec.TypeAuthorization, recovery.EncodeAuthorizationPayload(b))
	appendRec(t, w, id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressContentReceived))
	return id
}

func TestRecoverAfterJAppendCatalogFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal")
	inner, err := journal.OpenFileSegment(path)
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()

	cs := &journal.CrashSegment{Inner: inner, Dir: dir}
	id := seedAuthFileJournal(t, cs)
	seedPrefix, err := journal.ReadPrefix(cs)
	if err != nil {
		t.Fatal(err)
	}
	seedN := len(seedPrefix.Records)
	seedSize := cs.Size()

	t.Run(journal.CrashJAppendPre, func(t *testing.T) {
		if err := inner.Truncate(seedSize); err != nil {
			t.Fatal(err)
		}
		cs.FailAt = ""
		w, _, err := journal.OpenWriter(cs)
		if err != nil {
			t.Fatal(err)
		}
		cs.FailAt = journal.CrashJAppendPre
		_, err = w.Append(id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressPrepared))
		if !journal.IsInjectedCrash(err) {
			t.Fatalf("want injected crash, got %v", err)
		}
		p, err := journal.ReadPrefix(cs)
		if err != nil || p.Torn || len(p.Records) != seedN {
			t.Fatalf("prefix err=%v torn=%v n=%d", err, p.Torn, len(p.Records))
		}
		out, err := recovery.Recover(p, obsOK(), recovery.Policy{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if out.TornTail {
			t.Fatalf("PRE must not report torn: %+v", out)
		}
	})

	t.Run(journal.CrashJAppendMid, func(t *testing.T) {
		if err := inner.Truncate(seedSize); err != nil {
			t.Fatal(err)
		}
		cs.FailAt = ""
		w, _, err := journal.OpenWriter(cs)
		if err != nil {
			t.Fatal(err)
		}
		cs.FailAt = journal.CrashJAppendMid
		_, err = w.Append(id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressPrepared))
		if !journal.IsInjectedCrash(err) {
			t.Fatalf("want injected crash, got %v", err)
		}
		p, err := journal.ReadPrefix(cs)
		if err != nil || !p.Torn || len(p.Records) != seedN {
			t.Fatalf("prefix err=%v torn=%v n=%d", err, p.Torn, len(p.Records))
		}
		out, err := recovery.Recover(p, obsOK(), recovery.Policy{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !out.TornTail || out.State != recovery.StateQuarantined {
			t.Fatalf("%+v", out)
		}
		out2, err := recovery.RecoverAgain(p, obsOK(), recovery.Policy{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !out2.IdempotentNoop || out2.State != out.State {
			t.Fatalf("again: %+v", out2)
		}
		// Quarantine truncate then clean re-append must succeed.
		if err := inner.Truncate(p.Bytes); err != nil {
			t.Fatal(err)
		}
		cs.FailAt = ""
		w2, _, err := journal.OpenWriter(cs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w2.Append(id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressPrepared)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run(journal.CrashJAppendPost, func(t *testing.T) {
		if err := inner.Truncate(seedSize); err != nil {
			t.Fatal(err)
		}
		cs.FailAt = ""
		w, _, err := journal.OpenWriter(cs)
		if err != nil {
			t.Fatal(err)
		}
		cs.FailAt = journal.CrashJAppendPost
		_, err = w.Append(id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressPrepared))
		if !journal.IsInjectedCrash(err) {
			t.Fatalf("want injected crash, got %v", err)
		}
		p, err := journal.ReadPrefix(cs)
		if err != nil || p.Torn || len(p.Records) != seedN+1 {
			t.Fatalf("prefix err=%v torn=%v n=%d", err, p.Torn, len(p.Records))
		}
		out, err := recovery.Recover(p, obsOK(), recovery.Policy{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if out.TornTail {
			t.Fatalf("POST durable bytes must not look torn: %+v", out)
		}
	})

	t.Run(journal.CrashJMetaPost, func(t *testing.T) {
		if err := inner.Truncate(seedSize); err != nil {
			t.Fatal(err)
		}
		cs.FailAt = ""
		w, _, err := journal.OpenWriter(cs)
		if err != nil {
			t.Fatal(err)
		}
		cs.FailAt = journal.CrashJMetaPost
		_, err = w.Append(id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressPrepared))
		if !journal.IsInjectedCrash(err) {
			t.Fatalf("want injected crash, got %v", err)
		}
		p, err := journal.ReadPrefix(cs)
		if err != nil || p.Torn || len(p.Records) != seedN+1 {
			t.Fatalf("prefix err=%v torn=%v n=%d", err, p.Torn, len(p.Records))
		}
		out, err := recovery.Recover(p, obsOK(), recovery.Policy{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if out.TornTail {
			t.Fatalf("META durable record must not look torn: %+v", out)
		}
	})
}
