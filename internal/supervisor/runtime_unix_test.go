//go:build unix

package supervisor_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

func TestRuntimeStartChildIPC(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "integris-role-stub")
	ctxBuild, cancelBuild := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelBuild()
	if err := launcher.BuildGoPackage(ctxBuild, root, "./cmd/integris-role-stub", bin); err != nil {
		t.Fatal(err)
	}

	p, err := supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:     authority.RoleNet,
			Confer:   []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{authority.RoleParser},
		},
		{
			Role:     authority.RoleParser,
			Confer:   []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{authority.RoleNet},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x66}, 32)
	var nonce [16]byte
	nonce[2] = 3
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleNet, authority.RoleParser)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("runtime"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteFrame(parent.Conn, raw); err != nil {
		t.Fatal(err)
	}
	respRaw, err := ipc.ReadFrame(parent.Conn, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := parent.Chan.Decode(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(resp.Payload, []byte("ack:runtime|NEG-FS:")) {
		t.Fatalf("%q", resp.Payload)
	}
	for _, tok := range []string{"|NEG-EXEC:", "|NEG-PTRACE:", "|NEG-PARSER-NET:", "|NEG-ROLE-NET:"} {
		if !bytes.Contains(resp.Payload, []byte(tok)) {
			t.Fatalf("missing %s in %q", tok, resp.Payload)
		}
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-PARSER-NET:denied_as_expected")) {
		t.Fatalf("parser role semantic probe missing/failed in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|KEY:"+launcher.KeyTransportSCMRights)) {
		t.Fatalf("missing default scm key in %q", resp.Payload)
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd", "freebsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS:denied_as_expected")) {
			t.Fatalf("expected NEG-FS denial on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
			t.Fatalf("expected NEG-FS-READ denial on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-EXEC:denied_as_expected")) {
			t.Fatalf("expected NEG-EXEC denial on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-ROLE-NET:denied_as_expected")) {
			t.Fatalf("expected NEG-ROLE-NET denial on %s: %q", runtime.GOOS, resp.Payload)
		}
	}
	if err := rt.WaitChild(authority.RoleParser); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRestartChildIPC(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "integris-role-stub")
	ctxBuild, cancelBuild := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelBuild()
	if err := launcher.BuildGoPackage(ctxBuild, root, "./cmd/integris-role-stub", bin); err != nil {
		t.Fatal(err)
	}

	p, err := supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:     authority.RoleNet,
			Confer:   []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{authority.RoleParser},
		},
		{
			Role:     authority.RoleParser,
			Confer:   []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{authority.RoleNet},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x68}, 32)
	var nonce [16]byte
	nonce[2] = 5
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, bin); err != nil {
		t.Fatal(err)
	}
	parent, err := rt.Fabric.Endpoint(authority.RoleNet, authority.RoleParser)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteFrame(parent.Conn, raw); err != nil {
		t.Fatal(err)
	}
	respRaw, err := ipc.ReadFrame(parent.Conn, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := parent.Chan.Decode(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(resp.Payload, []byte("ack:first|NEG-FS:")) {
		t.Fatalf("%q", resp.Payload)
	}
	if err := rt.WaitChild(authority.RoleParser); err != nil {
		t.Fatal(err)
	}

	if err := rt.RestartChild(ctx, authority.RoleParser, authority.RoleNet, bin); err != nil {
		t.Fatal(err)
	}
	parent, err = rt.Fabric.Endpoint(authority.RoleNet, authority.RoleParser)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = parent.Chan.Encode(ipc.TypeRequest, []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteFrame(parent.Conn, raw); err != nil {
		t.Fatal(err)
	}
	respRaw, err = ipc.ReadFrame(parent.Conn, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = parent.Chan.Decode(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(resp.Payload, []byte("ack:second|NEG-FS:")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|KEY:"+launcher.KeyTransportSCMRights)) {
		t.Fatalf("missing scm key after restart in %q", resp.Payload)
	}
	if err := rt.WaitChild(authority.RoleParser); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildExtraFiles(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "integris-role-stub")
	ctxBuild, cancelBuild := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelBuild()
	if err := launcher.BuildGoPackage(ctxBuild, root, "./cmd/integris-role-stub", bin); err != nil {
		t.Fatal(err)
	}

	p, err := supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:     authority.RoleNet,
			Confer:   []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{authority.RoleParser},
		},
		{
			Role:     authority.RoleParser,
			Confer:   []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{authority.RoleNet},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x67}, 32)
	var nonce [16]byte
	nonce[2] = 4
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	rt.KeyViaExtraFiles = true

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleNet, authority.RoleParser)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("runtime-extra"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteFrame(parent.Conn, raw); err != nil {
		t.Fatal(err)
	}
	respRaw, err := ipc.ReadFrame(parent.Conn, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := parent.Chan.Decode(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(resp.Payload, []byte("ack:runtime-extra|NEG-FS:")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|KEY:"+launcher.KeyTransportAnonFile)) &&
		!bytes.Contains(resp.Payload, []byte("|KEY:"+launcher.KeyTransportMemfd)) {
		t.Fatalf("missing legacy key in %q", resp.Payload)
	}
	if err := rt.WaitChild(authority.RoleParser); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildAllowRoots(t *testing.T) {
	modRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "integris-role-stub")
	ctxBuild, cancelBuild := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelBuild()
	if err := launcher.BuildGoPackage(ctxBuild, modRoot, "./cmd/integris-role-stub", bin); err != nil {
		t.Fatal(err)
	}

	allowRoot := filepath.Join(t.TempDir(), "archive")
	if err := os.MkdirAll(allowRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	p, err := supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:     authority.RoleAuth,
			Confer:   []authority.Capability{authority.CapIdentityHandle, authority.CapSessionKeyDerive, authority.CapAuthorizationPolicy},
			IPCPeers: []authority.ProcessRole{authority.RoleApply},
		},
		{
			Role:     authority.RoleApply,
			Confer:   []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{authority.RoleAuth},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x69}, 32)
	var nonce [16]byte
	nonce[2] = 6
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	rt.AllowRoots = map[authority.ProcessRole][]string{
		authority.RoleApply: {allowRoot},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleAuth, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleAuth, authority.RoleApply)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("allow-roots"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteFrame(parent.Conn, raw); err != nil {
		t.Fatal(err)
	}
	respRaw, err := ipc.ReadFrame(parent.Conn, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := parent.Chan.Decode(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(resp.Payload, []byte("ack:allow-roots|NEG-FS:")) {
		t.Fatalf("%q", resp.Payload)
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:available")) {
			t.Fatalf("expected NEG-FS-PATH available on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-WRITE:available")) {
			t.Fatalf("expected NEG-FS-WRITE available for apply on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
			t.Fatalf("expected ambient NEG-FS-READ denial on %s: %q", runtime.GOOS, resp.Payload)
		}
	case "freebsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:skipped")) {
			t.Fatalf("expected NEG-FS-PATH skipped on freebsd: %q", resp.Payload)
		}
	}
	if err := rt.WaitChild(authority.RoleApply); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildAllowRootsIndex(t *testing.T) {
	modRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "integris-role-stub")
	ctxBuild, cancelBuild := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelBuild()
	if err := launcher.BuildGoPackage(ctxBuild, modRoot, "./cmd/integris-role-stub", bin); err != nil {
		t.Fatal(err)
	}

	allowRoot := filepath.Join(t.TempDir(), "archive-ro")
	if err := os.MkdirAll(allowRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(allowRoot, "marker.txt"), []byte("ro"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:     authority.RolePlan,
			Confer:   []authority.Capability{authority.CapCanonicalManifests, authority.CapPlanOutput},
			IPCPeers: []authority.ProcessRole{authority.RoleIndex},
		},
		{
			Role:     authority.RoleIndex,
			Confer:   []authority.Capability{authority.CapReadonlyArchiveRoot, authority.CapBoundedIndexOutput},
			IPCPeers: []authority.ProcessRole{authority.RolePlan},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x6b}, 32)
	var nonce [16]byte
	nonce[2] = 8
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	rt.AllowRoots = map[authority.ProcessRole][]string{
		authority.RoleIndex: {allowRoot},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleIndex, authority.RolePlan, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RolePlan, authority.RoleIndex)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("index-roots"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ipc.WriteFrame(parent.Conn, raw); err != nil {
		t.Fatal(err)
	}
	respRaw, err := ipc.ReadFrame(parent.Conn, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := parent.Chan.Decode(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(resp.Payload, []byte("ack:index-roots|NEG-FS:")) {
		t.Fatalf("%q", resp.Payload)
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:available")) {
			t.Fatalf("expected NEG-FS-PATH available on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-WRITE:denied_as_expected")) {
			t.Fatalf("expected NEG-FS-WRITE denial for index on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
			t.Fatalf("expected ambient NEG-FS-READ denial on %s: %q", runtime.GOOS, resp.Payload)
		}
	case "freebsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:skipped")) {
			t.Fatalf("expected NEG-FS-PATH skipped on freebsd: %q", resp.Payload)
		}
	}
	if err := rt.WaitChild(authority.RoleIndex); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRestartPairIPC(t *testing.T) {
	modRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "integris-role-stub")
	ctxBuild, cancelBuild := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelBuild()
	if err := launcher.BuildGoPackage(ctxBuild, modRoot, "./cmd/integris-role-stub", bin); err != nil {
		t.Fatal(err)
	}

	p, err := supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:     authority.RoleNet,
			Confer:   []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{authority.RoleParser},
		},
		{
			Role:     authority.RoleParser,
			Confer:   []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{authority.RoleNet},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x6a}, 32)
	var nonce [16]byte
	nonce[2] = 7
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	rt.KeyViaExtraFiles = true

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := rt.StartPair(ctx, authority.RoleParser, authority.RoleNet, authority.RoleParser, bin); err != nil {
		t.Fatal(err)
	}
	if err := rt.WaitChild(authority.RoleParser); err != nil {
		t.Fatal(err)
	}
	if err := rt.WaitChild(authority.RoleNet); err != nil {
		t.Fatal(err)
	}

	if err := rt.RestartPair(ctx, authority.RoleParser, authority.RoleNet, authority.RoleParser, bin); err != nil {
		t.Fatal(err)
	}
	if err := rt.WaitChild(authority.RoleParser); err != nil {
		t.Fatal(err)
	}
	if err := rt.WaitChild(authority.RoleNet); err != nil {
		t.Fatal(err)
	}
}
