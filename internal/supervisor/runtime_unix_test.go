//go:build unix

package supervisor_test

import (
	"bytes"
	"context"
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
	for _, tok := range []string{"|NEG-EXEC:", "|NEG-PTRACE:", "|NEG-PARSER-NET:"} {
		if !bytes.Contains(resp.Payload, []byte(tok)) {
			t.Fatalf("missing %s in %q", tok, resp.Payload)
		}
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-PARSER-NET:denied_as_expected")) {
		t.Fatalf("parser role semantic probe missing/failed in %q", resp.Payload)
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd", "freebsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS:denied_as_expected")) {
			t.Fatalf("expected NEG-FS denial on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-EXEC:denied_as_expected")) {
			t.Fatalf("expected NEG-EXEC denial on %s: %q", runtime.GOOS, resp.Payload)
		}
	}
	if err := rt.WaitChild(authority.RoleParser); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildSCM(t *testing.T) {
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
	rt.KeyViaSCM = true

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleParser, authority.RoleNet, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleNet, authority.RoleParser)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("runtime-scm"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:runtime-scm|NEG-FS:")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|KEY:"+launcher.KeyTransportSCMRights)) {
		t.Fatalf("missing scm key in %q", resp.Payload)
	}
	if err := rt.WaitChild(authority.RoleParser); err != nil {
		t.Fatal(err)
	}
}
