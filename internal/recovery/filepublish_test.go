package recovery_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gpicchiarelli/integris/internal/platform"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

func TestFilePublisherHappyPathRecoverPublished(t *testing.T) {
	root := t.TempDir()
	pub, err := recovery.NewFilePublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("published-object-v1")
	pub.ExpectedContent = payload
	if err := pub.Publish("obj", payload); err != nil {
		t.Fatal(err)
	}
	wantCP := []recovery.CrashLabel{
		recovery.LabelPStageCreate,
		recovery.LabelPStageSync,
		recovery.LabelPPublishRename,
		recovery.LabelPPublishDirSync,
	}
	if len(pub.Checkpoints) != len(wantCP) {
		t.Fatalf("checkpoints=%v", pub.Checkpoints)
	}
	for i, l := range wantCP {
		if pub.Checkpoints[i] != l {
			t.Fatalf("checkpoints=%v want %v", pub.Checkpoints, wantCP)
		}
	}
	has, err := pub.PublishedHas("obj")
	if err != nil || !has {
		t.Fatalf("published has=%v err=%v", has, err)
	}
	staged, err := pub.StagingHas("obj")
	if err != nil || staged {
		t.Fatalf("staging must be empty: has=%v err=%v", staged, err)
	}

	obs, err := pub.Observation(dig("root"), dig("vol"))
	if err != nil {
		t.Fatal(err)
	}
	if !obs.PublicationLinearized || !obs.PublishedContentMatches || obs.StagingPresent {
		t.Fatalf("%+v", obs)
	}

	p := prefixWithAuthChain(t, false)
	out, err := recovery.Recover(p, obs, recovery.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != recovery.StatePublished || !out.Published {
		t.Fatalf("%+v", out)
	}
}

func TestFilePublisherFailAtCatalog(t *testing.T) {
	payload := []byte("crash-object")

	cases := []struct {
		label      recovery.CrashLabel
		wantStage  bool
		wantPub    bool
		afterClear func(t *testing.T, pub *recovery.FilePublisher, payload []byte)
	}{
		{
			label:     recovery.LabelPStageCreate,
			wantStage: false,
			wantPub:   false,
			afterClear: func(t *testing.T, pub *recovery.FilePublisher, payload []byte) {
				t.Helper()
				if err := pub.Publish("obj", payload); err != nil {
					t.Fatal(err)
				}
				has, err := pub.PublishedHas("obj")
				if err != nil || !has {
					t.Fatalf("published has=%v err=%v", has, err)
				}
			},
		},
		{
			label:     recovery.LabelPStageSync,
			wantStage: true,
			wantPub:   false,
			afterClear: func(t *testing.T, pub *recovery.FilePublisher, payload []byte) {
				t.Helper()
				obs, err := pub.Observation(dig("root"), dig("vol"))
				if err != nil {
					t.Fatal(err)
				}
				if obs.PublicationLinearized || !obs.StagingPresent {
					t.Fatalf("%+v", obs)
				}
				p := prefixWithAuthChain(t, false)
				fp, err := recovery.NewFilePersist(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if err := fp.SeedStaging("obj", payload); err != nil {
					t.Fatal(err)
				}
				obs.PublicationStarted = true
				out, err := recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
				if err != nil {
					t.Fatal(err)
				}
				if out.State != recovery.StateQuarantined {
					t.Fatalf("%+v", out)
				}
			},
		},
		{
			label:     recovery.LabelPPublishRename,
			wantStage: true,
			wantPub:   false,
			afterClear: func(t *testing.T, pub *recovery.FilePublisher, payload []byte) {
				t.Helper()
				obs, err := pub.Observation(dig("root"), dig("vol"))
				if err != nil {
					t.Fatal(err)
				}
				if obs.PublicationLinearized || !obs.StagingPresent {
					t.Fatalf("%+v", obs)
				}
				pub.FailAt = ""
				if err := pub.Publish("obj2", payload); err != nil {
					t.Fatal(err)
				}
				has, err := pub.PublishedHas("obj2")
				if err != nil || !has {
					t.Fatalf("published has=%v err=%v", has, err)
				}
			},
		},
		{
			label:     recovery.LabelPPublishDirSync,
			wantStage: false,
			wantPub:   true,
			afterClear: func(t *testing.T, pub *recovery.FilePublisher, payload []byte) {
				t.Helper()
				pub.ExpectedContent = payload
				obs, err := pub.Observation(dig("root"), dig("vol"))
				if err != nil {
					t.Fatal(err)
				}
				if !obs.PublicationLinearized || !obs.PublishedContentMatches {
					t.Fatalf("rename durable before DIRSYNC: %+v", obs)
				}
				p := prefixWithAuthChain(t, false)
				out, err := recovery.Recover(p, obs, recovery.Policy{}, nil)
				if err != nil {
					t.Fatal(err)
				}
				if out.State != recovery.StatePublished {
					t.Fatalf("%+v", out)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.label), func(t *testing.T) {
			root := t.TempDir()
			pub, err := recovery.NewFilePublisher(root)
			if err != nil {
				t.Fatal(err)
			}
			pub.FailAt = tc.label
			pub.ExpectedContent = payload
			err = pub.Publish("obj", payload)
			if err == nil || !recovery.AsKind(err, recovery.KindIO) {
				t.Fatalf("want IO fault, got %v", err)
			}
			if len(pub.Checkpoints) == 0 || pub.Checkpoints[len(pub.Checkpoints)-1] != tc.label {
				t.Fatalf("checkpoints=%v", pub.Checkpoints)
			}
			staged, err := pub.StagingHas("obj")
			if err != nil || staged != tc.wantStage {
				t.Fatalf("staging has=%v want %v err=%v", staged, tc.wantStage, err)
			}
			published, err := pub.PublishedHas("obj")
			if err != nil || published != tc.wantPub {
				t.Fatalf("published has=%v want %v err=%v", published, tc.wantPub, err)
			}
			pub.FailAt = ""
			tc.afterClear(t, pub, payload)
		})
	}
}

func TestFilePublisherRejectsBadNameAndOverwrite(t *testing.T) {
	root := t.TempDir()
	pub, err := recovery.NewFilePublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Publish("../x", []byte("no")); err == nil || !recovery.AsKind(err, recovery.KindState) {
		t.Fatalf("want state err, got %v", err)
	}
	if err := pub.Publish("obj", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := pub.Publish("obj", []byte("b")); err == nil {
		t.Fatal("expected exclusive publish failure")
	}
	got, err := pub.PublishedHas("obj")
	if err != nil || !got {
		t.Fatal(err)
	}
	pub.ExpectedContent = []byte("a")
	obs, err := pub.Observation(dig("root"), dig("vol"))
	if err != nil || !obs.PublishedContentMatches {
		t.Fatalf("%+v err=%v", obs, err)
	}
}

func TestFilePublisherPublishFromClone(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.bin")
	payload := []byte("clone-publish-v1")
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err := recovery.NewFilePublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	pub.ExpectedContent = payload
	if err := pub.PublishFrom("obj", src); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" && pub.StageMechanism != platform.CloneMechanismClonefile {
		t.Fatalf("darwin StageMechanism=%q want clonefile", pub.StageMechanism)
	}
	if pub.StageMechanism != platform.CloneMechanismClonefile &&
		pub.StageMechanism != platform.CloneMechanismFiclone &&
		pub.StageMechanism != platform.CloneMechanismCopy {
		t.Fatalf("StageMechanism=%q", pub.StageMechanism)
	}
	has, err := pub.PublishedHas("obj")
	if err != nil || !has {
		t.Fatalf("published has=%v err=%v", has, err)
	}
	obs, err := pub.Observation(dig("root"), dig("vol"))
	if err != nil {
		t.Fatal(err)
	}
	if !obs.PublicationLinearized || !obs.PublishedContentMatches {
		t.Fatalf("%+v", obs)
	}
	p := prefixWithAuthChain(t, false)
	out, err := recovery.Recover(p, obs, recovery.Policy{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != recovery.StatePublished {
		t.Fatalf("%+v", out)
	}
}

func TestFilePublisherPublishFromFailAtCreate(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "source.bin")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, err := recovery.NewFilePublisher(root)
	if err != nil {
		t.Fatal(err)
	}
	pub.FailAt = recovery.LabelPStageCreate
	err = pub.PublishFrom("obj", src)
	if err == nil || !recovery.AsKind(err, recovery.KindIO) {
		t.Fatalf("want IO fault, got %v", err)
	}
	staged, err := pub.StagingHas("obj")
	if err != nil || staged {
		t.Fatalf("staging has=%v err=%v", staged, err)
	}
}
