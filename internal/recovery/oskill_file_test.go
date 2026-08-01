//go:build unix

package recovery_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

func buildCrashStub(t *testing.T) string {
	t.Helper()
	modRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "integris-crash-stub")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := launcher.BuildGoPackage(ctx, modRoot, "./cmd/integris-crash-stub", bin); err != nil {
		t.Fatal(err)
	}
	return bin
}

func runCrashStub(t *testing.T, bin, root, name, failAt, data string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return launcher.RunEngineering(ctx, launcher.ExecRequest{
		Executable:      bin,
		EngineeringMode: true,
		Env: []string{
			"INTEGRIS_CRASH_ROOT=" + root,
			"INTEGRIS_CRASH_NAME=" + name,
			"INTEGRIS_CRASH_FAIL_AT=" + failAt,
			"INTEGRIS_CRASH_DATA=" + data,
		},
	})
}

func TestOSKillFilePublisherCatalog(t *testing.T) {
	bin := buildCrashStub(t)
	payload := "os-kill-payload"

	cases := []struct {
		label     recovery.CrashLabel
		wantStage bool
		wantPub   bool
	}{
		{recovery.LabelPStageCreate, false, false},
		{recovery.LabelPStageSync, true, false},
		{recovery.LabelPPublishRename, true, false},
		{recovery.LabelPPublishDirSync, false, true},
	}

	for _, tc := range cases {
		t.Run(string(tc.label), func(t *testing.T) {
			root := t.TempDir()
			// Pre-create layout so Observation works even if CREATE kill races mkdir.
			pub, err := recovery.NewFilePublisher(root)
			if err != nil {
				t.Fatal(err)
			}
			err = runCrashStub(t, bin, root, "obj", string(tc.label), payload)
			if err == nil || !launcher.ExitSignaled(err) {
				t.Fatalf("want signaled exit, got %v", err)
			}
			staged, err := pub.StagingHas("obj")
			if err != nil || staged != tc.wantStage {
				t.Fatalf("staging has=%v want %v err=%v", staged, tc.wantStage, err)
			}
			published, err := pub.PublishedHas("obj")
			if err != nil || published != tc.wantPub {
				t.Fatalf("published has=%v want %v err=%v", published, tc.wantPub, err)
			}

			pub.ExpectedContent = []byte(payload)
			obs, err := pub.Observation(dig("root"), dig("vol"))
			if err != nil {
				t.Fatal(err)
			}
			p := prefixWithAuthChain(t, false)
			switch tc.label {
			case recovery.LabelPPublishDirSync:
				if !obs.PublicationLinearized || !obs.PublishedContentMatches {
					t.Fatalf("%+v", obs)
				}
				out, err := recovery.Recover(p, obs, recovery.Policy{}, nil)
				if err != nil {
					t.Fatal(err)
				}
				if out.State != recovery.StatePublished {
					t.Fatalf("%+v", out)
				}
			case recovery.LabelPStageCreate:
				if obs.StagingPresent || obs.PublicationLinearized {
					t.Fatalf("%+v", obs)
				}
			default:
				if obs.PublicationLinearized {
					t.Fatalf("must not claim linearized: %+v", obs)
				}
				fp, err := recovery.NewFilePersist(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if tc.wantStage {
					if err := fp.SeedStaging("obj", []byte(payload)); err != nil {
						t.Fatal(err)
					}
					obs.StagingPresent = true
					obs.PublicationStarted = true
				}
				out, err := recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
				if err != nil {
					t.Fatal(err)
				}
				if out.State != recovery.StateQuarantined {
					t.Fatalf("%+v", out)
				}
			}
		})
	}
}
