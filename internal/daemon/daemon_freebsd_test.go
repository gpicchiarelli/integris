//go:build freebsd

package daemon_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gpicchiarelli/integris/internal/daemon"
	"github.com/gpicchiarelli/integris/internal/remotesync"
)

// TestM3pStrictLaunchCapEnterPushServe is the FreeBSD supervised CapEnter
// push first cut: StrictLaunch Once product children (M3m–M3o fail-closed
// CapMode + Capsicum rights) complete a push with journal/audit artifacts.
func TestM3pStrictLaunchCapEnterPushServe(t *testing.T) {
	bin := buildIntegrisd(t)
	psk := make([]byte, remotesync.RootKeySize)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	src, dst := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(src, "a.txt"), "hello-m3p")
	mustWrite(t, filepath.Join(src, "d", "b.txt"), "nested-m3p")

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

	assertFile(t, filepath.Join(dst, "a.txt"), "hello-m3p")
	assertFile(t, filepath.Join(dst, "d", "b.txt"), "nested-m3p")
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "local.jrn")); err != nil {
		t.Fatalf("journal under CapEnter StrictLaunch: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "audit.events")); err != nil {
		t.Fatalf("audit sink under CapEnter StrictLaunch: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, ".integris", "last-plan.json")); err != nil {
		t.Fatalf("plan snapshot under CapEnter StrictLaunch: %v", err)
	}
}
