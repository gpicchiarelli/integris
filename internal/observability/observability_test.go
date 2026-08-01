package observability_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/observability"
)

func TestEmitAndSequence(t *testing.T) {
	s := observability.NewMemSink(10)
	e := observability.Event{
		ID:        "cfg.validated",
		Channel:   observability.ChannelOperational,
		Severity:  observability.SeverityInfo,
		Component: "config",
		Redaction: observability.RedactionPublic,
		Message:   "ok",
	}
	if err := s.Emit(e); err != nil {
		t.Fatal(err)
	}
	if err := s.Emit(e); err != nil {
		t.Fatal(err)
	}
	snap := s.Snapshot()
	if len(snap) != 2 || snap[0].Sequence != 1 || snap[1].Sequence != 2 {
		t.Fatalf("%+v", snap)
	}
}

func TestRejectSecretsInMessage(t *testing.T) {
	err := observability.Validate(observability.Event{
		ID: "x", Channel: observability.ChannelSecurity, Severity: observability.SeverityError,
		Component: "auth", Redaction: observability.RedactionPublic,
		Message: "-----BEGIN PRIVATE KEY-----",
	})
	if err == nil {
		t.Fatal("expected sanitize reject")
	}
}

func TestForbiddenRedaction(t *testing.T) {
	err := observability.Validate(observability.Event{
		ID: "x", Channel: observability.ChannelSecurity, Severity: observability.SeverityCritical,
		Component: "auth", Redaction: observability.RedactionForbidden, Message: "nope",
	})
	if err == nil {
		t.Fatal("expected redaction reject")
	}
}

func TestBackpressureDrop(t *testing.T) {
	s := observability.NewMemSink(1)
	e := observability.Event{
		ID: "d", Channel: observability.ChannelDiagnostic, Severity: observability.SeverityDebug,
		Component: "test", Redaction: observability.RedactionPublic,
	}
	if err := s.Emit(e); err != nil {
		t.Fatal(err)
	}
	if err := s.Emit(e); err == nil {
		t.Fatal("expected backpressure")
	}
	if s.Dropped() != 1 {
		t.Fatalf("dropped=%d", s.Dropped())
	}
}

func TestEncodeCanonicalStable(t *testing.T) {
	e := observability.Event{
		ID: "a", Channel: observability.ChannelAudit, Severity: observability.SeverityInfo,
		Component: "journal", CauseCategory: "append", Redaction: observability.RedactionInternal,
		Message: "committed", Sequence: 7,
	}
	b1, err := observability.EncodeCanonical(e)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := observability.EncodeCanonical(e)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatal("unstable encoding")
	}
}

func TestPathPseudonymOpaque(t *testing.T) {
	a := observability.PathPseudonym([]byte("key"), []byte("/secret/path"))
	b := observability.PathPseudonym([]byte("key"), []byte("/secret/path"))
	if a != b {
		t.Fatal("unstable")
	}
	c := observability.PathPseudonym([]byte("key"), []byte("/other"))
	if a == c {
		t.Fatal("expected distinct")
	}
}
