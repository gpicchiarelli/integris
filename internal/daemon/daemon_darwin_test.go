//go:build darwin && cgo

package daemon_test

import (
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

// TestM4eStrictLaunchSeatbeltPushServe is the Darwin supervised Seatbelt
// StrictLaunch push first cut: release-mode children (M2k + M3q/M4d
// fail-closed ambient FS-read + ROLE-NET) complete a push with
// journal/audit/plan artifacts under sandbox_init.
func TestM4eStrictLaunchSeatbeltPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m4e")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m4e")

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

	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m4e")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m4e")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("journal under Seatbelt StrictLaunch: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "audit.events")); err != nil {
		t.Fatalf("audit sink under Seatbelt StrictLaunch: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot under Seatbelt StrictLaunch: %v", err)
	}
}

// TestM4fStrictLaunchSeatbeltRestartOneApply is the Darwin supervised Seatbelt
// RestartOne first cut: StrictLaunch persistent serve, kill apply after the
// first push, assert net PID + listen addr survive, then push again (M3q/M4d
// fail-closed confine on replacement apply/journal/audit; M3r Darwin parity).
func TestM4fStrictLaunchSeatbeltRestartOneApply(t *testing.T) {
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
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m4f-seatbelt")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatalf("first push: %v", err)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4f-seatbelt")
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
		t.Fatal("timeout waiting for RestartOne ready under Seatbelt StrictLaunch")
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
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m4f-seatbelt")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4f-seatbelt")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m4f-seatbelt")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "audit.events")); err != nil {
		t.Fatalf("audit sink after RestartOne: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot after RestartOne: %v", err)
	}
}

// TestM4gStrictLaunchSeatbeltRestartOneParserDown is Darwin Seatbelt
// StrictLaunch coverage for M2v: kill parser after the first push; net+auth
// survive; parser→plan→index→apply→journal→audit respawn under M3q/M4d
// fail-closed confine; second push succeeds (M3u Darwin parity).
func TestM4gStrictLaunchSeatbeltRestartOneParserDown(t *testing.T) {
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
	mustWrite(t, filepath.Join(src1, "before.txt"), "before-m4g-seatbelt")
	if _, err := remotesync.Push(remotesync.PushOptions{
		Addr: addr1, Source: src1, RootKey: psk,
	}); err != nil {
		t.Fatalf("first push: %v", err)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4g-seatbelt")
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
		t.Fatal("timeout waiting for parser-down RestartOne ready under Seatbelt StrictLaunch")
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
	mustWrite(t, filepath.Join(src2, "after.txt"), "after-m4g-seatbelt")
	res := pushAfterRestart(t, remotesync.PushOptions{
		Addr: addr2, Source: src2, RootKey: psk,
	})
	if res.Outcome != "success" {
		t.Fatalf("%+v", res)
	}
	assertFile(t, filepath.Join(dst, "before.txt"), "before-m4g-seatbelt")
	assertFile(t, filepath.Join(dst, "after.txt"), "after-m4g-seatbelt")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "audit.events")); err != nil {
		t.Fatalf("audit sink after parser-down: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot after parser-down: %v", err)
	}
}
