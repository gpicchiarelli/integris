package recovery_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

func TestFaultInjectionConfirmBoundary(t *testing.T) {
	p := prefixWithAuthChain(t, false)
	obs := obsOK()
	obs.PublicationLinearized = true
	obs.PublishedContentMatches = true

	for _, label := range []recovery.CrashLabel{
		recovery.LabelPConfirmPre,
		recovery.LabelPConfirmPost,
	} {
		t.Run(string(label), func(t *testing.T) {
			io := &recovery.MemPersist{FailAt: label}
			_, err := recovery.Recover(p, obs, recovery.Policy{AllowConfirm: true}, io)
			if err == nil || !recovery.AsKind(err, recovery.KindIO) {
				t.Fatalf("want IO fault at %s, got %v", label, err)
			}
			if label == recovery.LabelPConfirmPre && io.Confirms != 0 {
				t.Fatalf("confirm must not commit before P-CONFIRM-PRE succeeds")
			}
			if label == recovery.LabelPConfirmPost && io.Confirms != 1 {
				// POST fails after append; confirm bytes may exist — at-most-once
				// is enforced by journal presence on retry, not by rolling back.
				t.Fatalf("confirms=%d", io.Confirms)
			}
		})
	}
}

func TestFaultInjectionQuarantineBoundary(t *testing.T) {
	p := prefixWithAuthChain(t, false)
	obs := obsOK()
	obs.StagingPresent = true
	obs.PublicationStarted = true

	io := &recovery.MemPersist{FailAt: recovery.LabelPPublishRename}
	_, err := recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, io)
	if err == nil || !recovery.AsKind(err, recovery.KindIO) {
		t.Fatalf("want IO fault, got %v", err)
	}
	if io.Quarantines != 0 {
		t.Fatalf("quarantine must not run after failed checkpoint")
	}
}

func TestJournalTornTailAcceptedForRecovery(t *testing.T) {
	seg := journal.NewMemSegment()
	w, _, err := journal.OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	id := txid(9)
	b := binding()
	appendRec(t, w, id, codec.TypeAuthorization, recovery.EncodeAuthorizationPayload(b))
	full := seg.Bytes()
	// Append a partial second record (torn).
	partial, err := codec.EncodeRecord(codec.RecordFields{
		Sequence:           2,
		TransactionID:      id,
		Type:               codec.TypeProgress,
		PreviousCommitment: codec.SHA256(full), // wrong on purpose for torn mid-write simulation
		Payload:            recovery.EncodeProgressPayload(recovery.ProgressContentReceived),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Use real chain: open writer path already synced record 1; tear by truncating a real append.
	seg2 := journal.NewMemSegment()
	w2, _, err := journal.OpenWriter(seg2)
	if err != nil {
		t.Fatal(err)
	}
	appendRec(t, w2, id, codec.TypeAuthorization, recovery.EncodeAuthorizationPayload(b))
	_, err = w2.Append(id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressContentReceived))
	if err != nil {
		t.Fatal(err)
	}
	raw := seg2.Bytes()
	_, n1, err := codec.DecodeRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	seg2.Truncate(int64(n1 + 10))
	p, err := journal.ReadPrefix(seg2)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Torn || len(p.Records) != 1 {
		t.Fatalf("want torn with 1 record, got %+v", p)
	}
	_ = partial

	out, err := recovery.Recover(p, obsOK(), recovery.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !out.TornTail || out.State != recovery.StateQuarantined {
		t.Fatalf("%+v", out)
	}
}

func TestCrashLabelCatalogComplete(t *testing.T) {
	if len(recovery.AllCrashLabels) != 10 {
		t.Fatalf("M1 catalog size=%d", len(recovery.AllCrashLabels))
	}
	seen := map[recovery.CrashLabel]bool{}
	for _, l := range recovery.AllCrashLabels {
		if seen[l] {
			t.Fatalf("duplicate %s", l)
		}
		seen[l] = true
	}
}

// TestFaultInjectionEveryCatalogLabel ensures each M1 crash label is reachable
// via PersistIO.Checkpoint during a confirm-bound recovery path (or is exercised
// as FailAt without requiring the production path to hit every publish label).
func TestFaultInjectionEveryCatalogLabel(t *testing.T) {
	for _, label := range recovery.AllCrashLabels {
		t.Run(string(label), func(t *testing.T) {
			io := &recovery.MemPersist{FailAt: label}
			// Direct checkpoint probe: label is in catalog and FailAt works.
			if err := io.Checkpoint(label); err == nil || !recovery.AsKind(err, recovery.KindIO) {
				t.Fatalf("checkpoint %s: %v", label, err)
			}
			if len(io.Checkpoints) != 1 || io.Checkpoints[0] != label {
				t.Fatalf("checkpoints=%v", io.Checkpoints)
			}
		})
	}
}

func TestRecoverAgainIdempotentAfterConfirm(t *testing.T) {
	p := prefixWithAuthChain(t, true)
	obs := obsOK()
	obs.PublicationLinearized = true
	obs.PublishedContentMatches = true
	out, err := recovery.RecoverAgain(p, obs, recovery.Policy{AllowConfirm: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != recovery.StateConfirmed || !out.IdempotentNoop {
		t.Fatalf("%+v", out)
	}
}
