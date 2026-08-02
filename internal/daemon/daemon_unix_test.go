//go:build unix

package daemon_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/daemon"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/remotesync"
)

func TestM2aPushServeSplit(t *testing.T) {
	rootMod, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "integrisd")
	ctxBuild, cancelBuild := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelBuild()
	if err := launcher.BuildGoPackage(ctxBuild, rootMod, "./cmd/integrisd", bin); err != nil {
		t.Fatal(err)
	}

	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m2a")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m2a")

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		errCh <- daemon.Serve(ctx, daemon.ServeOptions{
			Addr:           "127.0.0.1:0",
			Destination:    dst,
			RootKey:        psk,
			Once:           true,
			DisableAuth:    true,
			DisableParser:  true, // M2a: net↔apply only
			DisableAudit:   true,
			DisableJournal: true,
			DisablePlan:    true,
			Executable:     bin,
			Ready:          ready,
		})
	}()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("serve failed before ready: %v", err)
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for integrisd ready")
	}

	res, err := remotesync.Push(remotesync.PushOptions{
		Addr:    addr,
		Source:  src,
		RootKey: psk,
	})
	if err != nil {
		t.Fatalf("push: %v (serve: %v)", err, <-errCh)
	}
	if res.Outcome != "success" || res.FilesSent != 2 {
		t.Fatalf("%+v", res)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve wait timeout")
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m2a")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m2a")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("expected journal: %v", err)
	}
}

func TestNetApplyPlan(t *testing.T) {
	p, err := daemon.NetApplyPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Children) != 2 {
		t.Fatalf("children=%d", len(p.Children))
	}
}

func TestAuthNetApplyPlan(t *testing.T) {
	p, err := daemon.AuthNetApplyPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Children) != 3 {
		t.Fatalf("children=%d", len(p.Children))
	}
}

func TestM2cAuthPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m2c")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m2c")

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		errCh <- daemon.Serve(ctx, daemon.ServeOptions{
			Addr:           "127.0.0.1:0",
			Destination:    dst,
			RootKey:        psk,
			Once:           true,
			DisableParser:  true, // M2c: auth without parser
			DisableAudit:   true,
			DisableJournal: true,
			DisablePlan:    true,
			Executable:     bin,
			Ready:          ready,
		})
	}()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("serve failed before ready: %v", err)
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for integrisd ready")
	}

	res, err := remotesync.Push(remotesync.PushOptions{
		Addr:    addr,
		Source:  src,
		RootKey: psk,
	})
	if err != nil {
		t.Fatalf("push: %v (serve: %v)", err, <-errCh)
	}
	if res.Outcome != "success" || res.FilesSent != 2 {
		t.Fatalf("%+v", res)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve wait timeout")
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m2c")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m2c")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("expected journal: %v", err)
	}
}

func TestAuthParserNetApplyPlan(t *testing.T) {
	p, err := daemon.AuthParserNetApplyPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Children) != 4 {
		t.Fatalf("children=%d", len(p.Children))
	}
}

func TestM2dParserPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m2d")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m2d")

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		errCh <- daemon.Serve(ctx, daemon.ServeOptions{
			Addr:           "127.0.0.1:0",
			Destination:    dst,
			RootKey:        psk,
			Once:           true,
			DisableAudit:   true, // M2d: auth+parser without audit/journal
			DisableJournal: true,
			DisablePlan:    true,
			Executable:     bin,
			Ready:          ready,
		})
	}()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("serve failed before ready: %v", err)
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for integrisd ready")
	}

	res, err := remotesync.Push(remotesync.PushOptions{
		Addr:    addr,
		Source:  src,
		RootKey: psk,
	})
	if err != nil {
		t.Fatalf("push: %v (serve: %v)", err, <-errCh)
	}
	if res.Outcome != "success" || res.FilesSent != 2 {
		t.Fatalf("%+v", res)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve wait timeout")
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m2d")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m2d")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("expected journal: %v", err)
	}
}

func TestAuthParserNetApplyAuditPlan(t *testing.T) {
	p, err := daemon.AuthParserNetApplyAuditPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Children) != 5 {
		t.Fatalf("children=%d", len(p.Children))
	}
}

func TestM2eAuditPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m2e")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m2e")

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		errCh <- daemon.Serve(ctx, daemon.ServeOptions{
			Addr:           "127.0.0.1:0",
			Destination:    dst,
			RootKey:        psk,
			Once:           true,
			DisableJournal: true, // M2e: apply↔audit without journal role
			DisablePlan:    true,
			Executable:     bin,
			Ready:          ready,
		})
	}()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("serve failed before ready: %v", err)
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for integrisd ready")
	}

	res, err := remotesync.Push(remotesync.PushOptions{
		Addr:    addr,
		Source:  src,
		RootKey: psk,
	})
	if err != nil {
		t.Fatalf("push: %v (serve: %v)", err, <-errCh)
	}
	if res.Outcome != "success" || res.FilesSent != 2 {
		t.Fatalf("%+v", res)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve wait timeout")
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m2e")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m2e")
	auditPath := filepath.Join(dst, ".integris", "audit.events")
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("expected audit sink: %v", err)
	}
	if !bytes.Contains(raw, []byte("push.commit")) {
		t.Fatalf("audit missing push.commit: %q", raw)
	}
}

func TestAuthParserNetApplyJournalAuditPlan(t *testing.T) {
	p, err := daemon.AuthParserNetApplyJournalAuditPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Children) != 6 {
		t.Fatalf("children=%d", len(p.Children))
	}
}

func TestM2fJournalPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m2f")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m2f")

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		errCh <- daemon.Serve(ctx, daemon.ServeOptions{
			Addr:        "127.0.0.1:0",
			Destination: dst,
			RootKey:     psk,
			Once:        true,
			DisablePlan: true, // M2f: journal+audit without plan role
			Executable:  bin,
			Ready:       ready,
		})
	}()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("serve failed before ready: %v", err)
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for integrisd ready")
	}

	res, err := remotesync.Push(remotesync.PushOptions{
		Addr:    addr,
		Source:  src,
		RootKey: psk,
	})
	if err != nil {
		t.Fatalf("push: %v (serve: %v)", err, <-errCh)
	}
	if res.Outcome != "success" || res.FilesSent != 2 {
		t.Fatalf("%+v", res)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve wait timeout")
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m2f")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m2f")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("expected journal: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dst, ".integris", "audit.events"))
	if err != nil {
		t.Fatalf("expected audit sink: %v", err)
	}
	if !bytes.Contains(raw, []byte("push.commit")) {
		t.Fatalf("audit missing push.commit: %q", raw)
	}
}

func TestAuthParserNetPlanApplyJournalAuditPlan(t *testing.T) {
	p, err := daemon.AuthParserNetPlanApplyJournalAuditPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Children) != 7 {
		t.Fatalf("children=%d", len(p.Children))
	}
	var planPeers []authority.ProcessRole
	for _, c := range p.Children {
		if c.Role == authority.RolePlan {
			planPeers = c.IPCPeers
		}
	}
	if len(planPeers) != 2 {
		t.Fatalf("plan peers=%v", planPeers)
	}
	hasParser, hasApply := false, false
	for _, peer := range planPeers {
		if peer == authority.RoleParser {
			hasParser = true
		}
		if peer == authority.RoleApply {
			hasApply = true
		}
	}
	if !hasParser || !hasApply {
		t.Fatalf("plan peers want parser+apply, got %v", planPeers)
	}
}

func TestM2gPlanPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m2g")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m2g")

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		errCh <- daemon.Serve(ctx, daemon.ServeOptions{
			Addr:         "127.0.0.1:0",
			Destination:  dst,
			RootKey:      psk,
			Once:         true,
			DisableIndex: true, // M2g: plan without index
			Executable:   bin,
			Ready:        ready,
		})
	}()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("serve failed before ready: %v", err)
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for integrisd ready")
	}

	res, err := remotesync.Push(remotesync.PushOptions{
		Addr:    addr,
		Source:  src,
		RootKey: psk,
	})
	if err != nil {
		t.Fatalf("push: %v (serve: %v)", err, <-errCh)
	}
	if res.Outcome != "success" || res.FilesSent != 2 {
		t.Fatalf("%+v", res)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve wait timeout")
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m2g")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m2g")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("expected journal: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dst, ".integris", "audit.events"))
	if err != nil {
		t.Fatalf("expected audit sink: %v", err)
	}
	if !bytes.Contains(raw, []byte("push.commit")) {
		t.Fatalf("audit missing push.commit: %q", raw)
	}
}

func TestAuthParserNetPlanIndexApplyJournalAuditPlan(t *testing.T) {
	p, err := daemon.AuthParserNetPlanIndexApplyJournalAuditPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Children) != 8 {
		t.Fatalf("children=%d", len(p.Children))
	}
}

func TestM2hIndexPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m2h")
	mustWrite(t, filepath.Join(src, "same.txt"), "unchanged")
	mustWrite(t, filepath.Join(dst, "same.txt"), "unchanged")
	mustWrite(t, filepath.Join(dst, "old.txt"), "will-replace")
	mustWrite(t, filepath.Join(src, "old.txt"), "replaced")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m2h")

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		errCh <- daemon.Serve(ctx, daemon.ServeOptions{
			Addr:        "127.0.0.1:0",
			Destination: dst,
			RootKey:     psk,
			Once:        true,
			Executable:  bin,
			Ready:       ready,
			// M2h default: auth+parser+plan+index+journal+audit
		})
	}()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("serve failed before ready: %v", err)
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for integrisd ready")
	}

	res, err := remotesync.Push(remotesync.PushOptions{
		Addr:    addr,
		Source:  src,
		RootKey: psk,
	})
	if err != nil {
		t.Fatalf("push: %v (serve: %v)", err, <-errCh)
	}
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve wait timeout")
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m2h")
	assertFile(t, filepath.Join(dst, "same.txt"), "unchanged")
	assertFile(t, filepath.Join(dst, "old.txt"), "replaced")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m2h")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("expected journal: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dst, ".integris", "audit.events"))
	if err != nil {
		t.Fatalf("expected audit sink: %v", err)
	}
	if !bytes.Contains(raw, []byte("push.commit")) {
		t.Fatalf("audit missing push.commit: %q", raw)
	}
}

func TestM2kStrictLaunchRefusesPartialTopology(t *testing.T) {
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	_, err := daemon.Start(context.Background(), daemon.ServeOptions{
		Addr:         "127.0.0.1:0",
		Destination:  t.TempDir(),
		RootKey:      psk,
		StrictLaunch: true,
		DisableIndex: true, // not full chain
		Executable:   buildIntegrisd(t),
	})
	if err == nil {
		t.Fatal("expected strict launch to refuse DisableIndex")
	}
}

func TestM2kStrictLaunchPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m2k")

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		errCh <- daemon.Serve(ctx, daemon.ServeOptions{
			Addr:         "127.0.0.1:0",
			Destination:  dst,
			RootKey:      psk,
			Once:         true,
			StrictLaunch: true,
			Executable:   bin,
			Ready:        ready,
		})
	}()

	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("serve failed before ready: %v", err)
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for integrisd ready")
	}

	res, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr, Source: src, RootKey: psk,
	})
	if err != nil {
		t.Fatalf("push: %v (serve: %v)", err, <-errCh)
	}
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve wait timeout")
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m2k")
}

func TestM2iPeerAllowListPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	alice := make([]byte, remotesync.RootKeySize)
	bob := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(alice); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(bob); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m2i")
	marker := filepath.Join(dst, "untouched.txt")
	mustWrite(t, marker, "keep")

	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:        "127.0.0.1:0",
		Destination: dst,
		Peers: remotesync.PeerKeyring{
			"alice": alice,
			"bob":   bob,
		},
		Once:        false,
		MaxRestarts: 2,
		Executable:  bin,
		Ready:       ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr := <-ready

	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr, Source: src, RootKey: alice, PeerID: "eve",
	}); err == nil {
		t.Fatal("expected unknown peer rejection")
	}
	assertFile(t, marker, "keep")
	if _, err := os.Lstat(filepath.Join(dst, "a.txt")); err == nil {
		t.Fatal("destination mutated after unknown peer")
	}

	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr, Source: src, RootKey: alice, PeerID: "bob",
	}); err == nil {
		t.Fatal("expected wrong-key rejection")
	}
	assertFile(t, marker, "keep")

	res, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr, Source: src, RootKey: alice, PeerID: "alice",
	})
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m2i")
	assertFile(t, marker, "keep")

	deadline := time.Now().Add(5 * time.Second)
	var auditRaw []byte
	for time.Now().Before(deadline) {
		auditRaw, err = os.ReadFile(filepath.Join(dst, ".integris", "audit.events"))
		if err == nil && bytes.Contains(auditRaw, []byte("auth.peer.admit")) &&
			bytes.Contains(auditRaw, []byte("auth.peer.deny")) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bytes.Contains(auditRaw, []byte("auth.peer.deny")) {
		t.Fatalf("audit missing auth.peer.deny: %q", auditRaw)
	}
	if !bytes.Contains(auditRaw, []byte("auth.peer.admit")) {
		t.Fatalf("audit missing auth.peer.admit: %q", auditRaw)
	}
	eveDigest := remotesync.PeerIDDigest("eve")
	aliceDigest := remotesync.PeerIDDigest("alice")
	if !bytes.Contains(auditRaw, []byte(eveDigest)) {
		t.Fatalf("audit missing eve digest %s: %q", eveDigest, auditRaw)
	}
	if !bytes.Contains(auditRaw, []byte(aliceDigest)) {
		t.Fatalf("audit missing alice digest %s: %q", aliceDigest, auditRaw)
	}
}

func TestM2bMultiPushPersistent(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:           "127.0.0.1:0",
		Destination:    dst,
		RootKey:        psk,
		Once:           false,
		MaxRestarts:    2,
		DisableAuth:    true,
		DisableParser:  true, // M2a/M2b: net↔apply only
		DisableAudit:   true,
		DisableJournal: true,
		DisablePlan:    true,
		Executable:     bin,
		Ready:          ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr := <-ready
	for i, name := range []string{"one.txt", "two.txt"} {
		src := t.TempDir()
		mustWrite(t, filepath.Join(src, name), fmt.Sprintf("payload-%d", i))
		res, err := remotesync.Push(remotesync.PushOptions{
			Addr: addr, Source: src, RootKey: psk,
		})
		if err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
		if res.Outcome != "success" {
			t.Fatalf("%+v", res)
		}
		assertFile(t, filepath.Join(dst, name), fmt.Sprintf("payload-%d", i))
	}
	st := srv.Status()
	if st.Restarts != 0 || st.ListenAddr != addr {
		t.Fatalf("status=%+v", st)
	}
}

func TestM2oRestartOneApply(t *testing.T) {
	// M2o: kill apply; net PID and listen addr survive via RestartOne.
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:           "127.0.0.1:0",
		Destination:    dst,
		RootKey:        psk,
		Once:           false,
		MaxRestarts:    2,
		DisableAuth:    true,
		DisableParser:  true,
		DisableAudit:   true,
		DisableJournal: true,
		DisablePlan:    true,
		Executable:     bin,
		Ready:          ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	netPID, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID == 0 {
		t.Fatal("missing net PID")
	}
	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-rebind")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleApply); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	netPID2, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID2 != netPID {
		t.Fatalf("net PID changed: %d → %d", netPID, netPID2)
	}
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart count, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-rebind")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-rebind")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-rebind")
}

func TestM3bRestartOneAuditAuthExtraPeer(t *testing.T) {
	// M3b: M2h+Peers audit/apply subtree death; rebind auth ExtraPeer→audit; auth PID survives.
	bin := buildIntegrisd(t)
	alice := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(alice); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:        "127.0.0.1:0",
		Destination: dst,
		Peers:       remotesync.PeerKeyring{"alice": alice},
		Once:        false,
		MaxRestarts: 2,
		Executable:  bin,
		Ready:       ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	survivors := []authority.ProcessRole{
		authority.RoleAuth, authority.RoleNet, authority.RoleParser,
		authority.RolePlan, authority.RoleIndex,
	}
	survivorPIDs := make(map[authority.ProcessRole]int, len(survivors))
	for _, role := range survivors {
		pid, ok := srv.ChildPID(role)
		if !ok || pid == 0 {
			t.Fatalf("missing %s PID", role)
		}
		survivorPIDs[role] = pid
	}
	auditPID, ok := srv.ChildPID(authority.RoleAudit)
	if !ok || auditPID == 0 {
		t.Fatal("missing audit PID")
	}

	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m3b-audit")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: alice, PeerID: "alice",
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleAudit); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	for role, want := range survivorPIDs {
		got, ok := srv.ChildPID(role)
		if !ok || got != want {
			t.Fatalf("%s PID changed: %d → %d", role, want, got)
		}
	}
	auditPID2, ok := srv.ChildPID(authority.RoleAudit)
	if !ok || auditPID2 == 0 {
		t.Fatal("audit not restarted")
	}
	if auditPID2 == auditPID {
		t.Fatal("audit PID unchanged after kill")
	}
	for _, role := range []authority.ProcessRole{
		authority.RoleApply, authority.RoleJournal,
	} {
		if _, ok := srv.ChildPID(role); !ok {
			t.Fatalf("%s not restarted", role)
		}
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m3b-audit")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: alice, PeerID: "alice",
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m3b-audit")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m3b-audit")

	deadline := time.Now().Add(5 * time.Second)
	var auditRaw []byte
	for time.Now().Before(deadline) {
		auditRaw, err = os.ReadFile(filepath.Join(dst, ".integris", "audit.events"))
		if err == nil && bytes.Count(auditRaw, []byte("auth.peer.admit")) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if bytes.Count(auditRaw, []byte("auth.peer.admit")) < 2 {
		t.Fatalf("expected ≥2 auth.peer.admit after auth ExtraPeer rebind: %q", auditRaw)
	}
}

func TestM3aRestartOneAuthPeerAuditExtraPeer(t *testing.T) {
	// M3a: M2h+Peers auth death; rebind net primary + audit ExtraPeer; survivors keep PIDs.
	bin := buildIntegrisd(t)
	alice := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(alice); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:        "127.0.0.1:0",
		Destination: dst,
		Peers:       remotesync.PeerKeyring{"alice": alice},
		Once:        false,
		MaxRestarts: 2,
		Executable:  bin,
		Ready:       ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	survivors := []authority.ProcessRole{
		authority.RoleNet, authority.RoleParser, authority.RolePlan,
		authority.RoleIndex, authority.RoleApply, authority.RoleJournal,
		authority.RoleAudit,
	}
	survivorPIDs := make(map[authority.ProcessRole]int, len(survivors))
	for _, role := range survivors {
		pid, ok := srv.ChildPID(role)
		if !ok || pid == 0 {
			t.Fatalf("missing %s PID", role)
		}
		survivorPIDs[role] = pid
	}
	authPID, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID == 0 {
		t.Fatal("missing auth PID")
	}

	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m3a-auth")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: alice, PeerID: "alice",
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleAuth); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	for role, want := range survivorPIDs {
		got, ok := srv.ChildPID(role)
		if !ok || got != want {
			t.Fatalf("%s PID changed: %d → %d", role, want, got)
		}
	}
	authPID2, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID2 == 0 {
		t.Fatal("auth not restarted")
	}
	if authPID2 == authPID {
		t.Fatal("auth PID unchanged after kill")
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m3a-auth")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: alice, PeerID: "alice",
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m3a-auth")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m3a-auth")

	deadline := time.Now().Add(5 * time.Second)
	var auditRaw []byte
	for time.Now().Before(deadline) {
		auditRaw, err = os.ReadFile(filepath.Join(dst, ".integris", "audit.events"))
		if err == nil {
			// At least two admits: before + after restart.
			if bytes.Count(auditRaw, []byte("auth.peer.admit")) >= 2 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if bytes.Count(auditRaw, []byte("auth.peer.admit")) < 2 {
		t.Fatalf("expected ≥2 auth.peer.admit after ExtraPeer rebind: %q", auditRaw)
	}
}

func TestM2wRestartOneAuthNetPrimary(t *testing.T) {
	// M2w: M2c auth death; respawn auth; rebind net primary→auth; net+apply survive.
	runAuthPrimaryRestart(t, "m2w", daemon.ServeOptions{
		DisableParser:  true,
		DisableAudit:   true,
		DisableJournal: true,
		DisablePlan:    true,
	}, []authority.ProcessRole{authority.RoleNet, authority.RoleApply})
}

func TestM2xRestartOneAuthNetPrimaryM2d(t *testing.T) {
	// M2x: M2d auth death; net+parser+apply survive.
	runAuthPrimaryRestart(t, "m2x", daemon.ServeOptions{
		DisableAudit:   true,
		DisableJournal: true,
		DisablePlan:    true,
	}, []authority.ProcessRole{
		authority.RoleNet, authority.RoleParser, authority.RoleApply,
	})
}

func TestM2yRestartOneAuthNetPrimaryM2g(t *testing.T) {
	// M2y: M2g auth death; net+parser+plan+apply+journal+audit survive.
	runAuthPrimaryRestart(t, "m2y", daemon.ServeOptions{
		DisableIndex: true,
	}, []authority.ProcessRole{
		authority.RoleNet, authority.RoleParser, authority.RolePlan,
		authority.RoleApply, authority.RoleJournal, authority.RoleAudit,
	})
}

func TestM2zRestartOneAuthNetPrimaryM2h(t *testing.T) {
	// M2z: M2h auth death; full data-plane survivors (shared PSK, no M2j).
	runAuthPrimaryRestart(t, "m2z", daemon.ServeOptions{}, []authority.ProcessRole{
		authority.RoleNet, authority.RoleParser, authority.RolePlan,
		authority.RoleIndex, authority.RoleApply, authority.RoleJournal,
		authority.RoleAudit,
	})
}

func runAuthPrimaryRestart(t *testing.T, tag string, base daemon.ServeOptions, survivors []authority.ProcessRole) {
	t.Helper()
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := base
	opts.Addr = "127.0.0.1:0"
	opts.Destination = dst
	opts.RootKey = psk
	opts.Once = false
	opts.MaxRestarts = 3
	opts.Executable = bin
	opts.Ready = ready

	srv, err := daemon.Start(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	survivorPIDs := make(map[authority.ProcessRole]int, len(survivors))
	for _, role := range survivors {
		pid, ok := srv.ChildPID(role)
		if !ok || pid == 0 {
			t.Fatalf("missing %s PID", role)
		}
		survivorPIDs[role] = pid
	}
	authPID, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID == 0 {
		t.Fatal("missing auth PID")
	}
	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-"+tag+"-auth")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleAuth); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	for role, want := range survivorPIDs {
		got, ok := srv.ChildPID(role)
		if !ok || got != want {
			t.Fatalf("%s PID changed: %d → %d", role, want, got)
		}
	}
	authPID2, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID2 == 0 {
		t.Fatal("auth not restarted")
	}
	if authPID2 == authPID {
		t.Fatal("auth PID unchanged after kill")
	}
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart count, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-"+tag+"-auth")
	// M3j: net may still be adopting the rebound primary peer FD; retry briefly.
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-"+tag+"-auth")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-"+tag+"-auth")
}

func TestM2pRestartOneApplyExtraPeer(t *testing.T) {
	// M2p: M2c auth+net ExtraPeer→apply; kill apply; net+auth PIDs survive.
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:           "127.0.0.1:0",
		Destination:    dst,
		RootKey:        psk,
		Once:           false,
		MaxRestarts:    2,
		DisableParser:  true, // M2c: auth without parser; net ExtraPeer=apply
		DisableAudit:   true,
		DisableJournal: true,
		DisablePlan:    true,
		Executable:     bin,
		Ready:          ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	netPID, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID == 0 {
		t.Fatal("missing net PID")
	}
	authPID, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID == 0 {
		t.Fatal("missing auth PID")
	}
	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-extrapeer-rebind")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleApply); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	netPID2, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID2 != netPID {
		t.Fatalf("net PID changed: %d → %d", netPID, netPID2)
	}
	authPID2, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID2 != authPID {
		t.Fatalf("auth PID changed: %d → %d", authPID, authPID2)
	}
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart count, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-extrapeer-rebind")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-extrapeer-rebind")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-extrapeer-rebind")
}

func TestM2qRestartOneApplyParserExtraPeer(t *testing.T) {
	// M2q: M2d parser ExtraPeer→apply; kill apply; parser/net/auth PIDs survive.
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:           "127.0.0.1:0",
		Destination:    dst,
		RootKey:        psk,
		Once:           false,
		MaxRestarts:    2,
		DisableAudit:   true, // M2d
		DisableJournal: true,
		DisablePlan:    true,
		Executable:     bin,
		Ready:          ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	parserPID, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID == 0 {
		t.Fatal("missing parser PID")
	}
	netPID, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID == 0 {
		t.Fatal("missing net PID")
	}
	authPID, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID == 0 {
		t.Fatal("missing auth PID")
	}
	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-parser-rebind")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleApply); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	parserPID2, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID2 != parserPID {
		t.Fatalf("parser PID changed: %d → %d", parserPID, parserPID2)
	}
	netPID2, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID2 != netPID {
		t.Fatalf("net PID changed: %d → %d", netPID, netPID2)
	}
	authPID2, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID2 != authPID {
		t.Fatalf("auth PID changed: %d → %d", authPID, authPID2)
	}
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart count, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-parser-rebind")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-parser-rebind")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-parser-rebind")
}

func TestM2rRestartOneApplyPlanExtraPeer(t *testing.T) {
	// M2r: M2g plan ExtraPeer→apply; kill apply; plan/parser/net/auth survive;
	// apply+journal+audit subtree respawns (journal EOF on apply death).
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:         "127.0.0.1:0",
		Destination:  dst,
		RootKey:      psk,
		Once:         false,
		MaxRestarts:  2,
		DisableIndex: true, // M2g: plan→apply (no index)
		Executable:   bin,
		Ready:        ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	planPID, ok := srv.ChildPID(authority.RolePlan)
	if !ok || planPID == 0 {
		t.Fatal("missing plan PID")
	}
	parserPID, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID == 0 {
		t.Fatal("missing parser PID")
	}
	netPID, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID == 0 {
		t.Fatal("missing net PID")
	}
	authPID, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID == 0 {
		t.Fatal("missing auth PID")
	}
	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-plan-rebind")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleApply); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	planPID2, ok := srv.ChildPID(authority.RolePlan)
	if !ok || planPID2 != planPID {
		t.Fatalf("plan PID changed: %d → %d", planPID, planPID2)
	}
	parserPID2, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID2 != parserPID {
		t.Fatalf("parser PID changed: %d → %d", parserPID, parserPID2)
	}
	netPID2, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID2 != netPID {
		t.Fatalf("net PID changed: %d → %d", netPID, netPID2)
	}
	authPID2, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID2 != authPID {
		t.Fatalf("auth PID changed: %d → %d", authPID, authPID2)
	}
	if _, ok := srv.ChildPID(authority.RoleApply); !ok {
		t.Fatal("apply not restarted")
	}
	if _, ok := srv.ChildPID(authority.RoleJournal); !ok {
		t.Fatal("journal not restarted")
	}
	if _, ok := srv.ChildPID(authority.RoleAudit); !ok {
		t.Fatal("audit not restarted")
	}
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart count, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-plan-rebind")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-plan-rebind")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-plan-rebind")
}

func TestM2sRestartOneApplyIndexExtraPeer(t *testing.T) {
	// M2s: M2h index ExtraPeer→apply; kill apply; index+upstream survive;
	// apply+journal+audit subtree respawns.
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:        "127.0.0.1:0",
		Destination: dst,
		RootKey:     psk,
		Once:        false,
		MaxRestarts: 2,
		Executable:  bin, // full M2h chain
		Ready:       ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	indexPID, ok := srv.ChildPID(authority.RoleIndex)
	if !ok || indexPID == 0 {
		t.Fatal("missing index PID")
	}
	planPID, ok := srv.ChildPID(authority.RolePlan)
	if !ok || planPID == 0 {
		t.Fatal("missing plan PID")
	}
	parserPID, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID == 0 {
		t.Fatal("missing parser PID")
	}
	netPID, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID == 0 {
		t.Fatal("missing net PID")
	}
	authPID, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID == 0 {
		t.Fatal("missing auth PID")
	}
	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-index-rebind")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleApply); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	indexPID2, ok := srv.ChildPID(authority.RoleIndex)
	if !ok || indexPID2 != indexPID {
		t.Fatalf("index PID changed: %d → %d", indexPID, indexPID2)
	}
	planPID2, ok := srv.ChildPID(authority.RolePlan)
	if !ok || planPID2 != planPID {
		t.Fatalf("plan PID changed: %d → %d", planPID, planPID2)
	}
	parserPID2, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID2 != parserPID {
		t.Fatalf("parser PID changed: %d → %d", parserPID, parserPID2)
	}
	netPID2, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID2 != netPID {
		t.Fatalf("net PID changed: %d → %d", netPID, netPID2)
	}
	authPID2, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID2 != authPID {
		t.Fatalf("auth PID changed: %d → %d", authPID, authPID2)
	}
	if _, ok := srv.ChildPID(authority.RoleApply); !ok {
		t.Fatal("apply not restarted")
	}
	if _, ok := srv.ChildPID(authority.RoleJournal); !ok {
		t.Fatal("journal not restarted")
	}
	if _, ok := srv.ChildPID(authority.RoleAudit); !ok {
		t.Fatal("audit not restarted")
	}
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart count, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-index-rebind")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-index-rebind")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-index-rebind")
}

func TestM2tRestartOneParserNetExtraPeer(t *testing.T) {
	// M2t: M2d parser death; respawn parser+apply; rebind net ExtraPeer→parser.
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:           "127.0.0.1:0",
		Destination:    dst,
		RootKey:        psk,
		Once:           false,
		MaxRestarts:    2,
		DisableAudit:   true, // M2d
		DisableJournal: true,
		DisablePlan:    true,
		Executable:     bin,
		Ready:          ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	netPID, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID == 0 {
		t.Fatal("missing net PID")
	}
	authPID, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID == 0 {
		t.Fatal("missing auth PID")
	}
	parserPID, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID == 0 {
		t.Fatal("missing parser PID")
	}
	applyPID, ok := srv.ChildPID(authority.RoleApply)
	if !ok || applyPID == 0 {
		t.Fatal("missing apply PID")
	}
	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-parser-kill")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleParser); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	netPID2, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID2 != netPID {
		t.Fatalf("net PID changed: %d → %d", netPID, netPID2)
	}
	authPID2, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID2 != authPID {
		t.Fatalf("auth PID changed: %d → %d", authPID, authPID2)
	}
	parserPID2, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID2 == 0 {
		t.Fatal("parser not restarted")
	}
	if parserPID2 == parserPID {
		t.Fatal("parser PID unchanged after kill")
	}
	applyPID2, ok := srv.ChildPID(authority.RoleApply)
	if !ok || applyPID2 == 0 {
		t.Fatal("apply not restarted")
	}
	if applyPID2 == applyPID {
		t.Fatal("apply PID unchanged after parser kill (expected respawn)")
	}
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart count, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-parser-kill")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-parser-kill")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-parser-kill")
}

func TestM2vRestartOneParserDownM2h(t *testing.T) {
	// M2v: M2h parser death; respawn parser→plan→index→apply→journal→audit; rebind net.
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:        "127.0.0.1:0",
		Destination: dst,
		RootKey:     psk,
		Once:        false,
		MaxRestarts: 2,
		// default M2h (index enabled)
		Executable: bin,
		Ready:      ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	netPID, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID == 0 {
		t.Fatal("missing net PID")
	}
	authPID, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID == 0 {
		t.Fatal("missing auth PID")
	}
	parserPID, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID == 0 {
		t.Fatal("missing parser PID")
	}
	indexPID, ok := srv.ChildPID(authority.RoleIndex)
	if !ok || indexPID == 0 {
		t.Fatal("missing index PID")
	}
	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m2v-parser")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleParser); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	netPID2, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID2 != netPID {
		t.Fatalf("net PID changed: %d → %d", netPID, netPID2)
	}
	authPID2, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID2 != authPID {
		t.Fatalf("auth PID changed: %d → %d", authPID, authPID2)
	}
	parserPID2, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID2 == 0 {
		t.Fatal("parser not restarted")
	}
	if parserPID2 == parserPID {
		t.Fatal("parser PID unchanged after kill")
	}
	indexPID2, ok := srv.ChildPID(authority.RoleIndex)
	if !ok || indexPID2 == 0 {
		t.Fatal("index not restarted")
	}
	if indexPID2 == indexPID {
		t.Fatal("index PID unchanged after parser kill (expected respawn)")
	}
	for _, role := range []authority.ProcessRole{
		authority.RolePlan, authority.RoleApply, authority.RoleJournal, authority.RoleAudit,
	} {
		if _, ok := srv.ChildPID(role); !ok {
			t.Fatalf("%s not restarted", role)
		}
	}
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart count, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m2v-parser")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m2v-parser")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m2v-parser")
}

func TestM2uRestartOneParserDownM2g(t *testing.T) {
	// M2u: M2g parser death; respawn parser→plan→apply→journal→audit; rebind net.
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:         "127.0.0.1:0",
		Destination:  dst,
		RootKey:      psk,
		Once:         false,
		MaxRestarts:  2,
		DisableIndex: true, // M2g
		Executable:   bin,
		Ready:        ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	netPID, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID == 0 {
		t.Fatal("missing net PID")
	}
	authPID, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID == 0 {
		t.Fatal("missing auth PID")
	}
	parserPID, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID == 0 {
		t.Fatal("missing parser PID")
	}
	planPID, ok := srv.ChildPID(authority.RolePlan)
	if !ok || planPID == 0 {
		t.Fatal("missing plan PID")
	}
	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m2u-parser")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleParser); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready")
	}
	if addr2 != addr1 {
		t.Fatalf("listen addr changed: %q → %q", addr1, addr2)
	}
	netPID2, ok := srv.ChildPID(authority.RoleNet)
	if !ok || netPID2 != netPID {
		t.Fatalf("net PID changed: %d → %d", netPID, netPID2)
	}
	authPID2, ok := srv.ChildPID(authority.RoleAuth)
	if !ok || authPID2 != authPID {
		t.Fatalf("auth PID changed: %d → %d", authPID, authPID2)
	}
	parserPID2, ok := srv.ChildPID(authority.RoleParser)
	if !ok || parserPID2 == 0 {
		t.Fatal("parser not restarted")
	}
	if parserPID2 == parserPID {
		t.Fatal("parser PID unchanged after kill")
	}
	planPID2, ok := srv.ChildPID(authority.RolePlan)
	if !ok || planPID2 == 0 {
		t.Fatal("plan not restarted")
	}
	if planPID2 == planPID {
		t.Fatal("plan PID unchanged after parser kill (expected respawn)")
	}
	for _, role := range []authority.ProcessRole{
		authority.RoleApply, authority.RoleJournal, authority.RoleAudit,
	} {
		if _, ok := srv.ChildPID(role); !ok {
			t.Fatalf("%s not restarted", role)
		}
	}
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart count, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m2u-parser")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m2u-parser")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m2u-parser")
}

func TestM2bRestartAfterKill(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:           "127.0.0.1:0",
		Destination:    dst,
		RootKey:        psk,
		Once:           false,
		MaxRestarts:    2,
		DisableAuth:    true,
		DisableParser:  true, // M2a/M2b: net↔apply only
		DisableAudit:   true,
		DisableJournal: true,
		DisablePlan:    true,
		Executable:     bin,
		Ready:          ready,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	addr1 := <-ready
	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-kill")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatal(err)
	}

	if err := srv.KillRole(authority.RoleApply); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for restart ready")
	}
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-kill")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-kill")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-kill")
}

var (
	integrisdBin     string
	integrisdBinErr  error
	integrisdBinOnce sync.Once
)

// pushAfterRestart retries Push while the data plane finishes peer-FD rebind (M3j).
func pushAfterRestart(t *testing.T, opts remotesync.PushOptions) remotesync.PushResult {
	t.Helper()
	var last error
	var res remotesync.PushResult
	for i := 0; i < 50; i++ {
		res, last = remotesync.Push(opts)
		if last == nil {
			return res
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("push after RestartOne: %v", last)
	return res
}

func buildIntegrisd(t *testing.T) string {
	t.Helper()
	integrisdBinOnce.Do(func() {
		rootMod, err := filepath.Abs(filepath.Join("..", ".."))
		if err != nil {
			integrisdBinErr = err
			return
		}
		bin := filepath.Join(os.TempDir(), fmt.Sprintf("integrisd-test-%d", os.Getpid()))
		ctxBuild, cancelBuild := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancelBuild()
		integrisdBinErr = launcher.BuildGoPackage(ctxBuild, rootMod, "./cmd/integrisd", bin)
		if integrisdBinErr == nil {
			integrisdBin = bin
		}
	})
	if integrisdBinErr != nil {
		t.Fatal(integrisdBinErr)
	}
	return integrisdBin
}

func mustWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte(want)) {
		t.Fatalf("got %q want %q", b, want)
	}
}
