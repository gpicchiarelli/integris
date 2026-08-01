//go:build unix

package recovery_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

func runJournalCrashStub(t *testing.T, bin, dir, failAt string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return launcher.RunEngineering(ctx, launcher.ExecRequest{
		Executable:      bin,
		EngineeringMode: true,
		Env: []string{
			"INTEGRIS_CRASH_MODE=journal",
			"INTEGRIS_CRASH_ROOT=" + dir,
			"INTEGRIS_CRASH_FAIL_AT=" + failAt,
		},
	})
}

func TestOSKillJournalJAppendCatalog(t *testing.T) {
	bin := buildCrashStub(t)
	seedN := 3 // plan + authorization + contentReceived

	cases := []struct {
		label    string
		wantTorn bool
		wantN    int
	}{
		{journal.CrashJAppendPre, false, seedN},
		{journal.CrashJAppendMid, true, seedN},
		{journal.CrashJAppendPost, false, seedN + 1},
		{journal.CrashJMetaPost, false, seedN + 1},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			dir := t.TempDir()
			err := runJournalCrashStub(t, bin, dir, tc.label)
			if err == nil || !launcher.ExitSignaled(err) {
				t.Fatalf("want signaled exit, got %v", err)
			}

			inner, err := journal.OpenFileSegment(filepath.Join(dir, "journal"))
			if err != nil {
				t.Fatal(err)
			}
			defer inner.Close()
			cs := &journal.CrashSegment{Inner: inner, Dir: dir}
			p, err := journal.ReadPrefix(cs)
			if err != nil || p.Torn != tc.wantTorn || len(p.Records) != tc.wantN {
				t.Fatalf("prefix err=%v torn=%v (want %v) n=%d (want %d)", err, p.Torn, tc.wantTorn, len(p.Records), tc.wantN)
			}

			out, err := recovery.Recover(p, obsOK(), recovery.Policy{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			switch tc.label {
			case journal.CrashJAppendMid:
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
			default:
				if out.TornTail {
					t.Fatalf("must not report torn: %+v", out)
				}
			}
		})
	}
}
