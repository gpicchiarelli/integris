package recovery_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/observability"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

func TestRecoverEmitsIrrecoverableEvent(t *testing.T) {
	sink := observability.NewMemSink(16)
	obs := recovery.FSObservation{
		PublicationLinearized:   true,
		PublishedContentMatches: true,
	}
	out, err := recovery.Recover(journal.Prefix{NextSequence: 1}, obs, recovery.Policy{Events: sink}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if out.State != recovery.StateIrrecoverable {
		t.Fatalf("state=%s", out.State)
	}
	ev := sink.Snapshot()
	if len(ev) != 1 || ev[0].ID != "recovery.irrecoverable" {
		t.Fatalf("events=%v", ev)
	}
	if ev[0].Channel != observability.ChannelSecurity {
		t.Fatalf("channel=%v", ev[0].Channel)
	}
}
