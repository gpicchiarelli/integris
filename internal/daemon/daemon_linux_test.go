//go:build linux

package daemon_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/daemon"
	"github.com/gpicchiarelli/integris/internal/remotesync"
)

// TestM4oStrictLaunchLandlockPushServe is the Linux supervised Landlock+seccomp
// StrictLaunch push first cut: release-mode children (M2k + M3q/M4d fail-closed
// ambient FS-read + ROLE-NET) complete a push with journal/audit/plan artifacts
// (M3p/M4e Linux parity).
func TestM4oStrictLaunchLandlockPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m4o")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m4o")

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

	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m4o")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m4o")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("journal under Landlock StrictLaunch: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "audit.events")); err != nil {
		t.Fatalf("audit sink under Landlock StrictLaunch: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot under Landlock StrictLaunch: %v", err)
	}
}

// TestM4pStrictLaunchLandlockRestartOneApply is the Linux supervised
// Landlock+seccomp RestartOne first cut: StrictLaunch persistent serve, kill
// apply after the first push, assert net PID + listen addr survive, then push
// again (M3q/M4d fail-closed confine on replacement apply/journal/audit;
// M3r/M4f Linux parity).
func TestM4pStrictLaunchLandlockRestartOneApply(t *testing.T) {
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
		StrictLaunch: true,
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
	indexPID, ok := srv.ChildPID(authority.RoleIndex)
	if !ok || indexPID == 0 {
		t.Fatal("missing index PID")
	}

	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m4p-landlock")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatalf("first push: %v", err)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4p-landlock")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("journal before RestartOne: %v", err)
	}

	if err := srv.KillRole(authority.RoleApply); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for RestartOne ready under Landlock StrictLaunch")
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
	indexPID2, ok := srv.ChildPID(authority.RoleIndex)
	if !ok || indexPID2 != indexPID {
		t.Fatalf("index PID changed: %d → %d", indexPID, indexPID2)
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
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m4p-landlock")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4p-landlock")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m4p-landlock")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "audit.events")); err != nil {
		t.Fatalf("audit sink after RestartOne: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot after RestartOne: %v", err)
	}
}

// TestM4qStrictLaunchLandlockRestartOneParserDown is Linux Landlock+seccomp
// StrictLaunch coverage for M2v: kill parser after the first push; net+auth
// survive; parser→plan→index→apply→journal→audit respawn under M3q/M4d
// fail-closed confine; second push succeeds (M3u/M4g Linux parity).
func TestM4qStrictLaunchLandlockRestartOneParserDown(t *testing.T) {
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
		StrictLaunch: true,
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
	indexPID, ok := srv.ChildPID(authority.RoleIndex)
	if !ok || indexPID == 0 {
		t.Fatal("missing index PID")
	}

	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m4q-landlock")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatalf("first push: %v", err)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4q-landlock")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("journal before parser-down: %v", err)
	}

	if err := srv.KillRole(authority.RoleParser); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for parser-down RestartOne ready under Landlock StrictLaunch")
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
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m4q-landlock")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4q-landlock")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m4q-landlock")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "audit.events")); err != nil {
		t.Fatalf("audit sink after parser-down: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot after parser-down: %v", err)
	}
}

// TestM4rStrictLaunchLandlockRestartOneAuthPrimary is Linux Landlock+seccomp
// StrictLaunch coverage for M2z: kill auth after the first push; net and the
// full data plane survive; auth respawns with primary peer rebind under
// M3q/M4d fail-closed confine; second push succeeds (M3v/M4h Linux parity).
func TestM4rStrictLaunchLandlockRestartOneAuthPrimary(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	survivors := []authority.ProcessRole{
		authority.RoleNet, authority.RoleParser, authority.RolePlan,
		authority.RoleIndex, authority.RoleApply, authority.RoleJournal,
		authority.RoleAudit,
	}
	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:         "127.0.0.1:0",
		Destination:  dst,
		RootKey:      psk,
		Once:         false,
		MaxRestarts:  3,
		StrictLaunch: true,
		Executable:   bin,
		Ready:        ready,
	})
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
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m4r-landlock")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatalf("first push: %v", err)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4r-landlock")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("journal before auth-primary RestartOne: %v", err)
	}

	if err := srv.KillRole(authority.RoleAuth); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for auth-primary RestartOne ready under Landlock StrictLaunch")
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
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m4r-landlock")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4r-landlock")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m4r-landlock")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "audit.events")); err != nil {
		t.Fatalf("audit sink after auth-primary RestartOne: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot after auth-primary RestartOne: %v", err)
	}
}

// TestM4sStrictLaunchLandlockRestartOneAuthPeerExtraPeer is Linux
// Landlock+seccomp StrictLaunch coverage for M3a: peer keyring; kill auth
// after the first push; net + full data plane survive; auth respawns with
// primary + audit ExtraPeer rebind under M3q/M4d fail-closed confine; second
// peer push admits again (M3w/M4i Linux parity).
func TestM4sStrictLaunchLandlockRestartOneAuthPeerExtraPeer(t *testing.T) {
	bin := buildIntegrisd(t)
	alice := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(alice); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	survivors := []authority.ProcessRole{
		authority.RoleNet, authority.RoleParser, authority.RolePlan,
		authority.RoleIndex, authority.RoleApply, authority.RoleJournal,
		authority.RoleAudit,
	}
	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:         "127.0.0.1:0",
		Destination:  dst,
		Peers:        remotesync.PeerKeyring{"alice": alice},
		Once:         false,
		MaxRestarts:  2,
		StrictLaunch: true,
		Executable:   bin,
		Ready:        ready,
	})
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
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m4s-landlock")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: alice, PeerID: "alice",
	}); err != nil {
		t.Fatalf("first push: %v", err)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4s-landlock")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("journal before peer-auth RestartOne: %v", err)
	}

	if err := srv.KillRole(authority.RoleAuth); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for peer-auth RestartOne ready under Landlock StrictLaunch")
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
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m4s-landlock")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: alice, PeerID: "alice",
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4s-landlock")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m4s-landlock")

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
		t.Fatalf("expected ≥2 auth.peer.admit after ExtraPeer rebind under Landlock: %q", auditRaw)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot after peer-auth RestartOne: %v", err)
	}
}

// TestM4tStrictLaunchLandlockRestartOneAuditAuthExtraPeer is Linux
// Landlock+seccomp StrictLaunch coverage for M3b: peer keyring; kill audit
// after the first push; auth+net+parser+plan+index survive; apply+journal+audit
// respawn with auth ExtraPeer→audit rebind under M3q/M4d fail-closed confine;
// second peer push admits again (M3x/M4j Linux parity).
func TestM4tStrictLaunchLandlockRestartOneAuditAuthExtraPeer(t *testing.T) {
	bin := buildIntegrisd(t)
	alice := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(alice); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	ready := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	survivors := []authority.ProcessRole{
		authority.RoleAuth, authority.RoleNet, authority.RoleParser,
		authority.RolePlan, authority.RoleIndex,
	}
	srv, err := daemon.Start(ctx, daemon.ServeOptions{
		Addr:         "127.0.0.1:0",
		Destination:  dst,
		Peers:        remotesync.PeerKeyring{"alice": alice},
		Once:         false,
		MaxRestarts:  2,
		StrictLaunch: true,
		Executable:   bin,
		Ready:        ready,
	})
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
	auditPID, ok := srv.ChildPID(authority.RoleAudit)
	if !ok || auditPID == 0 {
		t.Fatal("missing audit PID")
	}

	src1 := t.TempDir()
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m4t-landlock")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: alice, PeerID: "alice",
	}); err != nil {
		t.Fatalf("first push: %v", err)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4t-landlock")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("journal before audit ExtraPeer RestartOne: %v", err)
	}

	if err := srv.KillRole(authority.RoleAudit); err != nil {
		t.Fatal(err)
	}

	var addr2 string
	select {
	case addr2 = <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("timeout waiting for audit ExtraPeer RestartOne ready under Landlock StrictLaunch")
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
	st := srv.Status()
	if st.Restarts < 1 {
		t.Fatalf("expected restart count, status=%+v", st)
	}

	src2 := t.TempDir()
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m4t-landlock")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: alice, PeerID: "alice",
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4t-landlock")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m4t-landlock")

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
		t.Fatalf("expected ≥2 auth.peer.admit after audit ExtraPeer rebind under Landlock: %q", auditRaw)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot after audit ExtraPeer RestartOne: %v", err)
	}
}

// TestM4uStrictLaunchLandlockPeerPushServe is Linux Landlock+seccomp
// StrictLaunch Once coverage for M2j: peer keyring product children complete a
// peer push under M3q/M4d fail-closed confine with journal/audit/plan and ≥1
// admit (M3y/M4k Linux parity).
func TestM4uStrictLaunchLandlockPeerPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	alice := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(alice); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m4u")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m4u")

	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	go func() {
		errCh <- daemon.Serve(ctx, daemon.ServeOptions{
			Addr:         "127.0.0.1:0",
			Destination:  dst,
			Peers:        remotesync.PeerKeyring{"alice": alice},
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
		Addr: addr, Source: src, RootKey: alice, PeerID: "alice",
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

	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m4u")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m4u")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("journal under Landlock StrictLaunch peer push: %v", err)
	}
	auditRaw, err := os.ReadFile(filepath.Join(dst, ".integris", "audit.events"))
	if err != nil {
		t.Fatalf("audit sink under Landlock StrictLaunch peer push: %v", err)
	}
	if bytes.Count(auditRaw, []byte("auth.peer.admit")) < 1 {
		t.Fatalf("expected auth.peer.admit under Landlock peer push: %q", auditRaw)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot under Landlock StrictLaunch peer push: %v", err)
	}
}
