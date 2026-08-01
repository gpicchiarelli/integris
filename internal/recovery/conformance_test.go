package recovery_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

// Conformance notes (formal/transaction → Go):
//
// Abstract flags approximated by journal prefix + FSObservation:
//   authorized  ↔ TypeAuthorization present with matching root/volume digests
//   prepared    ↔ ProgressPrepared observed
//   verified    ↔ ProgressVerified observed
//   published   ↔ PublicationLinearized && PublishedContentMatches
//   confirmationCount ↔ number of TypeConfirmation records (at most one)
//
// These tests assert safety-shaped outcomes; they are not TLC proofs.

func TestConformanceNoInventedPublication(t *testing.T) {
	seg := journal.NewMemSegment()
	w, _, err := journal.OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	id := txid(3)
	b := binding()
	appendRec(t, w, id, codec.TypeAuthorization, recovery.EncodeAuthorizationPayload(b))
	// No progress / no FS publication.
	p, err := journal.ReadPrefix(seg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := recovery.Recover(p, obsOK(), recovery.Policy{AllowConfirm: true}, &recovery.MemPersist{})
	if err != nil {
		t.Fatal(err)
	}
	if out.State == recovery.StatePublished || out.State == recovery.StateConfirmed {
		t.Fatalf("must not invent publication: %+v", out)
	}
}

func TestConformanceConfirmationImpliesPublication(t *testing.T) {
	// Confirmation recorded without linearized publication must fail closed
	// (no additional confirmation append).
	p := prefixWithAuthChain(t, true)
	obs := obsOK()
	io := &recovery.MemPersist{}
	_, err := recovery.Recover(p, obs, recovery.Policy{AllowConfirm: true}, io)
	if err == nil {
		t.Fatal("expected refusal when confirmation lacks publication evidence")
	}
	if io.Confirms != 0 {
		t.Fatalf("must not append confirmation; confirms=%d", io.Confirms)
	}
}

func TestConformanceAtMostOneConfirmation(t *testing.T) {
	p := prefixWithAuthChain(t, true)
	obs := obsOK()
	obs.PublicationLinearized = true
	obs.PublishedContentMatches = true
	io := &recovery.MemPersist{}
	out, err := recovery.Recover(p, obs, recovery.Policy{AllowConfirm: true}, io)
	if err != nil {
		t.Fatal(err)
	}
	if io.Confirms != 0 {
		t.Fatalf("existing confirmation must not be re-appended: %d", io.Confirms)
	}
	if out.State != recovery.StateConfirmed {
		t.Fatalf("state=%s", out.State)
	}
}
