package recovery_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

func dig(s string) codec.Digest { return codec.SHA256([]byte(s)) }

func txid(n byte) codec.TransactionID {
	var id codec.TransactionID
	id[0] = n
	return id
}

func binding() recovery.AuthorizationBinding {
	return recovery.AuthorizationBinding{
		PlanDigest:             dig("plan"),
		ConfigurationDigest:    dig("cfg"),
		CapabilityVectorDigest: dig("cap"),
		RootIdentity:           dig("root"),
		VolumeIdentity:         dig("vol"),
		AuthDigest:             dig("auth"),
	}
}

func obsOK() recovery.FSObservation {
	return recovery.FSObservation{
		RootIdentity:   dig("root"),
		VolumeIdentity: dig("vol"),
	}
}

func appendRec(t *testing.T, w *journal.Writer, id codec.TransactionID, typ codec.RecordType, payload []byte) {
	t.Helper()
	if _, err := w.Append(id, typ, payload); err != nil {
		t.Fatal(err)
	}
}

func prefixWithAuthChain(t *testing.T, confirm bool) journal.Prefix {
	t.Helper()
	seg := journal.NewMemSegment()
	w, _, err := journal.OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	id := txid(1)
	b := binding()
	appendRec(t, w, id, codec.TypePlanDigest, b.PlanDigest[:])
	appendRec(t, w, id, codec.TypeAuthorization, recovery.EncodeAuthorizationPayload(b))
	appendRec(t, w, id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressContentReceived))
	appendRec(t, w, id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressPrepared))
	appendRec(t, w, id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressVerified))
	if confirm {
		appendRec(t, w, id, codec.TypeConfirmation, nil)
	}
	p, err := journal.ReadPrefix(seg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRecoverEmpty(t *testing.T) {
	out, err := recovery.Recover(journal.Prefix{NextSequence: 1}, obsOK(), recovery.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != recovery.StateCreated || !out.IdempotentNoop {
		t.Fatalf("%+v", out)
	}
}

func TestRecoverPublishedThenConfirmIdempotent(t *testing.T) {
	p := prefixWithAuthChain(t, false)
	obs := obsOK()
	obs.PublicationLinearized = true
	obs.PublishedContentMatches = true
	obs.PublicationStarted = true

	io := &recovery.MemPersist{}
	policy := recovery.Policy{AllowConfirm: true, AllowStagingCleanup: true}

	out1, err := recovery.Recover(p, obs, policy, io)
	if err != nil {
		t.Fatal(err)
	}
	if out1.State != recovery.StateConfirmed || io.Confirms != 1 {
		t.Fatalf("first: state=%s confirms=%d", out1.State, io.Confirms)
	}

	// Simulate durable confirmation now present in journal.
	p2 := prefixWithAuthChain(t, true)
	out2, err := recovery.Recover(p2, obs, policy, io)
	if err != nil {
		t.Fatal(err)
	}
	if out2.State != recovery.StateConfirmed || io.Confirms != 1 {
		t.Fatalf("second confirm duplicated: state=%s confirms=%d", out2.State, io.Confirms)
	}
	if !out2.IdempotentNoop {
		t.Fatal("expected idempotent noop")
	}
}

func TestRecoverNotLinearizedQuarantines(t *testing.T) {
	p := prefixWithAuthChain(t, false)
	obs := obsOK()
	obs.StagingPresent = true
	obs.PublicationStarted = true

	io := &recovery.MemPersist{}
	out, err := recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, io)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != recovery.StateQuarantined {
		t.Fatalf("state=%s", out.State)
	}
	if out.Published || io.Confirms != 0 {
		t.Fatalf("invented publish/confirm: %+v io=%+v", out, io)
	}
	if io.Quarantines != 1 {
		t.Fatalf("quarantines=%d", io.Quarantines)
	}

	// Second recovery: staging already gone.
	obs.StagingPresent = false
	obs.PublicationStarted = false
	io2 := &recovery.MemPersist{}
	// Journal still has no cancel/quarantine record; without staging, still quarantine decision.
	out2, err := recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, io2)
	if err != nil {
		t.Fatal(err)
	}
	if out2.State != recovery.StateQuarantined || io2.Quarantines != 0 {
		t.Fatalf("second: %+v quarantines=%d", out2, io2.Quarantines)
	}
}

func TestRecoverIdentityMismatch(t *testing.T) {
	p := prefixWithAuthChain(t, false)
	obs := obsOK()
	obs.RootIdentity = dig("other-root")
	_, err := recovery.Recover(p, obs, recovery.Policy{}, nil)
	if err == nil || !recovery.AsKind(err, recovery.KindIdentity) {
		t.Fatalf("want identity error, got %v", err)
	}
}

func TestRecoverNoInventPublication(t *testing.T) {
	p := prefixWithAuthChain(t, false)
	obs := obsOK()
	obs.PublicationLinearized = true
	obs.PublishedContentMatches = true
	// Break preparation chain by using prefix without progress — rebuild.
	seg := journal.NewMemSegment()
	w, _, err := journal.OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	id := txid(2)
	b := binding()
	appendRec(t, w, id, codec.TypeAuthorization, recovery.EncodeAuthorizationPayload(b))
	p, err = journal.ReadPrefix(seg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = recovery.Recover(p, obs, recovery.Policy{}, nil)
	if err == nil || !recovery.AsKind(err, recovery.KindFatal) {
		t.Fatalf("want fatal on invented publication chain, got %v", err)
	}
}

func TestRecoverCancellation(t *testing.T) {
	seg := journal.NewMemSegment()
	w, _, err := journal.OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	id := txid(3)
	b := binding()
	appendRec(t, w, id, codec.TypeAuthorization, recovery.EncodeAuthorizationPayload(b))
	appendRec(t, w, id, codec.TypeCancellation, nil)
	p, err := journal.ReadPrefix(seg)
	if err != nil {
		t.Fatal(err)
	}
	obs := obsOK()
	obs.StagingPresent = true
	io := &recovery.MemPersist{}
	out, err := recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, io)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != recovery.StateCancelled || io.Cleanups != 1 {
		t.Fatalf("%+v cleanups=%d", out, io.Cleanups)
	}
}

func TestDoubleRecoverStable(t *testing.T) {
	p := prefixWithAuthChain(t, true)
	obs := obsOK()
	obs.PublicationLinearized = true
	obs.PublishedContentMatches = true
	out1, err := recovery.Recover(p, obs, recovery.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := recovery.Recover(p, obs, recovery.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out1.State != recovery.StateConfirmed || out2.State != recovery.StateConfirmed {
		t.Fatalf("%s vs %s", out1.State, out2.State)
	}
	if !out2.IdempotentNoop {
		t.Fatal("expected noop")
	}
}
