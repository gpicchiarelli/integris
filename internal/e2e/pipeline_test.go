package e2e_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/path"
	"github.com/gpicchiarelli/integris/internal/plan"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

func dig(s string) codec.Digest { return codec.SHA256([]byte(s)) }

func TestM1PipelinePlanJournalRecover(t *testing.T) {
	comps := [][]byte{[]byte("dir"), []byte("a.txt")}
	if err := path.ValidateComponentsDefault(comps); err != nil {
		t.Fatal(err)
	}

	in := plan.CanonicalInput{
		ManifestDigest:         dig("manifest"),
		CapabilityVectorDigest: dig("capvec"),
		ConfigurationDigest:    dig("config"),
		Classifications: []plan.Classification{{
			Path: comps, CapabilityID: plan.CapTimes, Action: plan.ActionCreate,
			Result: plan.ResultLossless, RepresentationIDs: []uint16{1},
		}},
		Limits: plan.Limits{MaxEntries: 64, MaxPlanBytes: 1 << 20, MaxCapabilityComparisons: 64},
	}
	p, pf, err := plan.Build(in)
	if err != nil || !pf.Authorized() {
		t.Fatalf("plan: pf=%+v err=%v", pf, err)
	}

	seg := journal.NewMemSegment()
	w, _, err := journal.OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	var txid codec.TransactionID
	txid[0] = 0x42
	binding := recovery.AuthorizationBinding{
		PlanDigest:             p.Digest,
		ConfigurationDigest:    dig("config"),
		CapabilityVectorDigest: dig("capvec"),
		RootIdentity:           dig("root"),
		VolumeIdentity:         dig("vol"),
		AuthDigest:             dig("auth"),
	}
	if _, err := w.Append(txid, codec.TypePlanDigest, p.Digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(txid, codec.TypeAuthorization, recovery.EncodeAuthorizationPayload(binding)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(txid, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressContentReceived)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(txid, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressPrepared)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(txid, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressVerified)); err != nil {
		t.Fatal(err)
	}

	prefix, err := journal.ReadPrefix(seg)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	fp, err := recovery.NewFilePersist(root)
	if err != nil {
		t.Fatal(err)
	}
	obs := recovery.FSObservation{
		RootIdentity:            dig("root"),
		VolumeIdentity:          dig("vol"),
		PublicationLinearized:   true,
		PublishedContentMatches: true,
		PublicationStarted:      true,
	}
	out, err := recovery.Recover(prefix, obs, recovery.Policy{AllowConfirm: true, AllowStagingCleanup: true}, fp)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != recovery.StateConfirmed || fp.Confirms != 1 {
		t.Fatalf("state=%s confirms=%d", out.State, fp.Confirms)
	}

	if _, err := w.Append(txid, codec.TypeConfirmation, nil); err != nil {
		t.Fatal(err)
	}
	prefix2, err := journal.ReadPrefix(seg)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := recovery.RecoverAgain(prefix2, obs, recovery.Policy{AllowConfirm: true}, fp)
	if err != nil || !out2.IdempotentNoop || fp.Confirms != 1 {
		t.Fatalf("%+v confirms=%d err=%v", out2, fp.Confirms, err)
	}
}
