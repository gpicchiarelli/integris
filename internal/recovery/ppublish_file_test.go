package recovery_test

import (
	"path/filepath"
	"testing"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

func cancelPrefixWithAuth(t *testing.T) journal.Prefix {
	t.Helper()
	seg := journal.NewMemSegment()
	w, _, err := journal.OpenWriter(seg)
	if err != nil {
		t.Fatal(err)
	}
	id := txid(7)
	b := binding()
	appendRec(t, w, id, codec.TypeAuthorization, recovery.EncodeAuthorizationPayload(b))
	appendRec(t, w, id, codec.TypeCancellation, nil)
	p, err := journal.ReadPrefix(seg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRecoverAfterPPublishCatalogFile(t *testing.T) {
	t.Run(string(recovery.LabelPStageCreate), func(t *testing.T) {
		root := t.TempDir()
		fp, err := recovery.NewFilePersist(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := fp.SeedStaging("obj", []byte("staged")); err != nil {
			t.Fatal(err)
		}
		fp.FailAt = recovery.LabelPStageCreate
		p := cancelPrefixWithAuth(t)
		obs := obsOK()
		obs.StagingPresent = true
		_, err = recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
		if err == nil || !recovery.AsKind(err, recovery.KindIO) {
			t.Fatalf("want IO fault, got %v", err)
		}
		empty, err := fp.StagingEmpty()
		if err != nil || empty {
			t.Fatalf("staging must remain after CREATE fault: empty=%v err=%v", empty, err)
		}

		fp.FailAt = ""
		out, err := recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
		if err != nil {
			t.Fatal(err)
		}
		if out.State != recovery.StateCancelled {
			t.Fatalf("state=%s", out.State)
		}
		empty, err = fp.StagingEmpty()
		if err != nil || !empty {
			t.Fatalf("staging empty=%v err=%v", empty, err)
		}
	})

	t.Run(string(recovery.LabelPStageSync), func(t *testing.T) {
		root := t.TempDir()
		fp, err := recovery.NewFilePersist(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := fp.SeedStaging("obj", []byte("staged")); err != nil {
			t.Fatal(err)
		}
		fp.FailAt = recovery.LabelPStageSync
		p := cancelPrefixWithAuth(t)
		obs := obsOK()
		obs.StagingPresent = true
		_, err = recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
		if err == nil || !recovery.AsKind(err, recovery.KindIO) {
			t.Fatalf("want IO fault, got %v", err)
		}
		empty, err := fp.StagingEmpty()
		if err != nil || !empty {
			t.Fatalf("cleanup must run before SYNC fault: empty=%v err=%v", empty, err)
		}

		fp.FailAt = ""
		obs.StagingPresent = false
		out, err := recovery.RecoverAgain(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
		if err != nil {
			t.Fatal(err)
		}
		if out.State != recovery.StateCancelled || !out.IdempotentNoop {
			t.Fatalf("%+v", out)
		}
	})

	t.Run(string(recovery.LabelPPublishRename), func(t *testing.T) {
		root := t.TempDir()
		fp, err := recovery.NewFilePersist(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := fp.SeedStaging("obj", []byte("x")); err != nil {
			t.Fatal(err)
		}
		fp.FailAt = recovery.LabelPPublishRename
		p := prefixWithAuthChain(t, false)
		obs := obsOK()
		obs.StagingPresent = true
		obs.PublicationStarted = true
		_, err = recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
		if err == nil || !recovery.AsKind(err, recovery.KindIO) {
			t.Fatalf("want IO fault, got %v", err)
		}
		has, err := fp.QuarantineHas("obj")
		if err != nil || has {
			t.Fatalf("quarantine must be empty after RENAME fault: has=%v err=%v", has, err)
		}

		fp.FailAt = ""
		out, err := recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
		if err != nil {
			t.Fatal(err)
		}
		if out.State != recovery.StateQuarantined {
			t.Fatalf("state=%s", out.State)
		}
		has, err = fp.QuarantineHas("obj")
		if err != nil || !has {
			t.Fatalf("quarantine has=%v err=%v", has, err)
		}
	})

	t.Run(string(recovery.LabelPPublishDirSync), func(t *testing.T) {
		root := t.TempDir()
		fp, err := recovery.NewFilePersist(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := fp.SeedStaging("obj", []byte("x")); err != nil {
			t.Fatal(err)
		}
		fp.FailAt = recovery.LabelPPublishDirSync
		p := prefixWithAuthChain(t, false)
		obs := obsOK()
		obs.StagingPresent = true
		obs.PublicationStarted = true
		_, err = recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
		if err == nil || !recovery.AsKind(err, recovery.KindIO) {
			t.Fatalf("want IO fault, got %v", err)
		}
		has, err := fp.QuarantineHas("obj")
		if err != nil || !has {
			t.Fatalf("rename must run before DIRSYNC fault: has=%v err=%v", has, err)
		}

		fp.FailAt = ""
		obs.StagingPresent = false
		out, err := recovery.RecoverAgain(p, obs, recovery.Policy{AllowStagingCleanup: true}, fp)
		if err != nil {
			t.Fatal(err)
		}
		if out.State != recovery.StateQuarantined || !out.IdempotentNoop {
			t.Fatalf("%+v", out)
		}
	})

	t.Run(string(recovery.LabelPConfirmPre), func(t *testing.T) {
		root := t.TempDir()
		fp, err := recovery.NewFilePersist(root)
		if err != nil {
			t.Fatal(err)
		}
		fp.FailAt = recovery.LabelPConfirmPre
		p := prefixWithAuthChain(t, false)
		obs := obsOK()
		obs.PublicationLinearized = true
		obs.PublishedContentMatches = true
		obs.PublicationStarted = true
		_, err = recovery.Recover(p, obs, recovery.Policy{AllowConfirm: true}, fp)
		if err == nil || !recovery.AsKind(err, recovery.KindIO) {
			t.Fatalf("want IO fault, got %v", err)
		}
		if fp.Confirms != 0 {
			t.Fatalf("confirms=%d", fp.Confirms)
		}
		matches, err := filepath.Glob(filepath.Join(root, "confirm.log"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("confirm.log must be absent: %v %v", matches, err)
		}

		fp.FailAt = ""
		out, err := recovery.Recover(p, obs, recovery.Policy{AllowConfirm: true}, fp)
		if err != nil {
			t.Fatal(err)
		}
		if out.State != recovery.StateConfirmed || fp.Confirms != 1 {
			t.Fatalf("state=%s confirms=%d", out.State, fp.Confirms)
		}
	})

	t.Run(string(recovery.LabelPConfirmPost), func(t *testing.T) {
		root := t.TempDir()
		fp, err := recovery.NewFilePersist(root)
		if err != nil {
			t.Fatal(err)
		}
		fp.FailAt = recovery.LabelPConfirmPost
		p := prefixWithAuthChain(t, false)
		obs := obsOK()
		obs.PublicationLinearized = true
		obs.PublishedContentMatches = true
		obs.PublicationStarted = true
		_, err = recovery.Recover(p, obs, recovery.Policy{AllowConfirm: true}, fp)
		if err == nil || !recovery.AsKind(err, recovery.KindIO) {
			t.Fatalf("want IO fault, got %v", err)
		}
		if fp.Confirms != 1 {
			t.Fatalf("append must complete before POST fault: confirms=%d", fp.Confirms)
		}

		// Durable confirmation now present in journal → no second append.
		fp.FailAt = ""
		p2 := prefixWithAuthChain(t, true)
		out, err := recovery.RecoverAgain(p2, obs, recovery.Policy{AllowConfirm: true}, fp)
		if err != nil {
			t.Fatal(err)
		}
		if out.State != recovery.StateConfirmed || !out.IdempotentNoop || fp.Confirms != 1 {
			t.Fatalf("%+v confirms=%d", out, fp.Confirms)
		}
	})
}

func TestMemPersistRecordsStageSyncAndPublishDirSync(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		p := cancelPrefixWithAuth(t)
		obs := obsOK()
		obs.StagingPresent = true
		io := &recovery.MemPersist{}
		out, err := recovery.Recover(p, obs, recovery.Policy{AllowStagingCleanup: true}, io)
		if err != nil {
			t.Fatal(err)
		}
		if out.State != recovery.StateCancelled {
			t.Fatalf("state=%s", out.State)
		}
		want := []recovery.CrashLabel{recovery.LabelPStageCreate, recovery.LabelPStageSync}
		if len(io.Checkpoints) != 2 || io.Checkpoints[0] != want[0] || io.Checkpoints[1] != want[1] {
			t.Fatalf("checkpoints=%v want %v", io.Checkpoints, want)
		}
	})

	t.Run("quarantine", func(t *testing.T) {
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
		want := []recovery.CrashLabel{recovery.LabelPPublishRename, recovery.LabelPPublishDirSync}
		if len(io.Checkpoints) != 2 || io.Checkpoints[0] != want[0] || io.Checkpoints[1] != want[1] {
			t.Fatalf("checkpoints=%v want %v", io.Checkpoints, want)
		}
	})
}
