package session_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/observability"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestSessionEmitsOnVersionFailure(t *testing.T) {
	sink := observability.NewMemSink(8)
	s := session.New([]session.Version{1})
	s.Events = sink
	if err := s.Negotiate(); err == nil {
		t.Fatal("expected version failure")
	}
	ev := sink.Snapshot()
	if len(ev) != 1 || ev[0].ID != "session.failed" {
		t.Fatalf("events=%v", ev)
	}
}
