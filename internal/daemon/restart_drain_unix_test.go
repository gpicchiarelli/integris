//go:build unix

package daemon

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
)

func TestFlushExitPending(t *testing.T) {
	ch := make(chan authority.ProcessRole, 8)
	ch <- authority.RoleApply
	ch <- authority.RoleJournal
	ch <- authority.RoleAudit
	flushExitPending(ch)
	select {
	case role := <-ch:
		t.Fatalf("expected empty channel, got %s", role)
	default:
	}
	// Idempotent on empty.
	flushExitPending(ch)
}
