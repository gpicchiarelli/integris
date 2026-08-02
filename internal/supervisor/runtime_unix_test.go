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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:runtime|")) {
		t.Fatalf("%q", resp.Payload)
	}
	for _, tok := range []string{"|NEG-EXEC:", "|NEG-PTRACE:", "|NEG-PARSER-NET:", "|NEG-PARSER-KEYS:", "|NEG-PARSER-ARCHIVES:", "|NEG-ROLE-NET:"} {
		if !bytes.Contains(resp.Payload, []byte(tok)) {
			t.Fatalf("missing %s in %q", tok, resp.Payload)
		}
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-PARSER-NET:denied_as_expected")) {
		t.Fatalf("parser role semantic probe missing/failed in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-PARSER-KEYS:denied_as_expected")) {
		t.Fatalf("missing NEG-PARSER-KEYS in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-PARSER-ARCHIVES:denied_as_expected")) {
		t.Fatalf("missing NEG-PARSER-ARCHIVES in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|KEY:"+launcher.KeyTransportSCMRights)) {
		t.Fatalf("missing default scm key in %q", resp.Payload)
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:skipped")) {
			t.Fatalf("expected NEG-CAP-MODE skipped on %s: %q", runtime.GOOS, resp.Payload)
		}
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
	case "freebsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:available")) {
			t.Fatalf("expected NEG-CAP-MODE available on freebsd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS:denied_as_expected")) {
			t.Fatalf("expected NEG-FS denial on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
			t.Fatalf("expected NEG-FS-READ denial on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-EXEC:denied_as_expected")) {
			t.Fatalf("expected NEG-EXEC denial on %s: %q", runtime.GOOS, resp.Payload)
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:first|")) {
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:second|")) {
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:runtime-extra|")) {
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:allow-roots|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-APPLY-KEYS:denied_as_expected")) {
		t.Fatalf("missing NEG-APPLY-KEYS in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-APPLY-PATH:denied_as_expected")) {
		t.Fatalf("missing NEG-APPLY-PATH in %q", resp.Payload)
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:skipped")) {
			t.Fatalf("expected NEG-CAP-MODE skipped on %s: %q", runtime.GOOS, resp.Payload)
		}
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
		if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:available")) {
			t.Fatalf("expected NEG-CAP-MODE available on freebsd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
			t.Fatalf("expected ambient NEG-FS-READ denial on freebsd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:available")) {
			t.Fatalf("expected NEG-FS-PATH available on freebsd via conferred dir fd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-WRITE:available")) {
			t.Fatalf("expected NEG-FS-WRITE available for apply on freebsd: %q", resp.Payload)
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:index-roots|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-INDEX-PUB:denied_as_expected")) {
		t.Fatalf("missing NEG-INDEX-PUB in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-INDEX-DELETE:denied_as_expected")) {
		t.Fatalf("missing NEG-INDEX-DELETE in %q", resp.Payload)
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:skipped")) {
			t.Fatalf("expected NEG-CAP-MODE skipped on %s: %q", runtime.GOOS, resp.Payload)
		}
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
		if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:available")) {
			t.Fatalf("expected NEG-CAP-MODE available on freebsd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
			t.Fatalf("expected ambient NEG-FS-READ denial on freebsd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:available")) {
			t.Fatalf("expected NEG-FS-PATH available on freebsd via conferred dir fd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-WRITE:denied_as_expected")) {
			t.Fatalf("expected NEG-FS-WRITE denial for index on freebsd: %q", resp.Payload)
		}
	}
	if err := rt.WaitChild(authority.RoleIndex); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildAllowRootsJournal(t *testing.T) {
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

	allowRoot := filepath.Join(t.TempDir(), "journal-root")
	if err := os.MkdirAll(allowRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	p, err := supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:     authority.RoleApply,
			Confer:   []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{authority.RoleJournal},
		},
		{
			Role: authority.RoleJournal,
			Confer: []authority.Capability{
				authority.CapJournalDescriptor, authority.CapAuthenticatedRecords,
			},
			IPCPeers: []authority.ProcessRole{authority.RoleApply},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x6f}, 32)
	var nonce [16]byte
	nonce[2] = 15
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	rt.AllowRoots = map[authority.ProcessRole][]string{
		authority.RoleJournal: {allowRoot},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleJournal, authority.RoleApply, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleApply, authority.RoleJournal)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("journal-roots"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:journal-roots|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-JOURNAL-NET:denied_as_expected")) {
		t.Fatalf("missing NEG-JOURNAL-NET in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-JOURNAL-POLICY:denied_as_expected")) {
		t.Fatalf("missing NEG-JOURNAL-POLICY in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-JOURNAL-MUTATE:denied_as_expected")) {
		t.Fatalf("missing NEG-JOURNAL-MUTATE in %q", resp.Payload)
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:skipped")) {
			t.Fatalf("expected NEG-CAP-MODE skipped on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:available")) {
			t.Fatalf("expected NEG-FS-PATH available on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-WRITE:available")) {
			t.Fatalf("expected NEG-FS-WRITE available for journal on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
			t.Fatalf("expected ambient NEG-FS-READ denial on %s: %q", runtime.GOOS, resp.Payload)
		}
	case "freebsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:available")) {
			t.Fatalf("expected NEG-CAP-MODE available on freebsd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
			t.Fatalf("expected ambient NEG-FS-READ denial on freebsd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:available")) {
			t.Fatalf("expected NEG-FS-PATH available on freebsd via conferred dir fd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-WRITE:available")) {
			t.Fatalf("expected NEG-FS-WRITE available for journal on freebsd: %q", resp.Payload)
		}
	}
	if err := rt.WaitChild(authority.RoleJournal); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildAllowRootsAudit(t *testing.T) {
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

	allowRoot := filepath.Join(t.TempDir(), "audit-root")
	if err := os.MkdirAll(allowRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(allowRoot, "marker.txt"), []byte("ro"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role: authority.RoleJournal,
			Confer: []authority.Capability{
				authority.CapJournalDescriptor, authority.CapAuthenticatedRecords,
			},
			IPCPeers: []authority.ProcessRole{authority.RoleAudit},
		},
		{
			Role: authority.RoleAudit,
			Confer: []authority.Capability{
				authority.CapReadonlyJournal, authority.CapRedactedEventSink,
			},
			IPCPeers: []authority.ProcessRole{authority.RoleJournal},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x70}, 32)
	var nonce [16]byte
	nonce[2] = 16
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	rt.AllowRoots = map[authority.ProcessRole][]string{
		authority.RoleAudit: {allowRoot},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleAudit, authority.RoleJournal, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleJournal, authority.RoleAudit)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("audit-roots"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:audit-roots|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-AUDIT-DECIDE:denied_as_expected")) {
		t.Fatalf("missing NEG-AUDIT-DECIDE in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-AUDIT-ARCHIVES:denied_as_expected")) {
		t.Fatalf("missing NEG-AUDIT-ARCHIVES in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-AUDIT-SECRETS:denied_as_expected")) {
		t.Fatalf("missing NEG-AUDIT-SECRETS in %q", resp.Payload)
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:skipped")) {
			t.Fatalf("expected NEG-CAP-MODE skipped on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:available")) {
			t.Fatalf("expected NEG-FS-PATH available on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-WRITE:denied_as_expected")) {
			t.Fatalf("expected NEG-FS-WRITE denial for audit on %s: %q", runtime.GOOS, resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
			t.Fatalf("expected ambient NEG-FS-READ denial on %s: %q", runtime.GOOS, resp.Payload)
		}
	case "freebsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:available")) {
			t.Fatalf("expected NEG-CAP-MODE available on freebsd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
			t.Fatalf("expected ambient NEG-FS-READ denial on freebsd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:available")) {
			t.Fatalf("expected NEG-FS-PATH available on freebsd via conferred dir fd: %q", resp.Payload)
		}
		if !bytes.Contains(resp.Payload, []byte("|NEG-FS-WRITE:denied_as_expected")) {
			t.Fatalf("expected NEG-FS-WRITE denial for audit on freebsd: %q", resp.Payload)
		}
	}
	if err := rt.WaitChild(authority.RoleAudit); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRestartChildAllowRoots(t *testing.T) {
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

	allowRoot := filepath.Join(t.TempDir(), "archive-restart")
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
	key := bytes.Repeat([]byte{0x71}, 32)
	var nonce [16]byte
	nonce[2] = 15
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	rt.AllowRoots = map[authority.ProcessRole][]string{
		authority.RoleApply: {allowRoot},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleApply, authority.RoleAuth, bin); err != nil {
		t.Fatal(err)
	}

	probe := func(label string) {
		t.Helper()
		parent, err := rt.Fabric.Endpoint(authority.RoleAuth, authority.RoleApply)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte(label))
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
		prefix := []byte("ack:" + label + "|")
		if !bytes.HasPrefix(resp.Payload, prefix) {
			t.Fatalf("%q", resp.Payload)
		}
		switch runtime.GOOS {
		case "darwin", "linux", "openbsd":
			if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:skipped")) {
				t.Fatalf("expected NEG-CAP-MODE skipped after %s on %s: %q", label, runtime.GOOS, resp.Payload)
			}
			if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:available")) {
				t.Fatalf("expected NEG-FS-PATH available after %s on %s: %q", label, runtime.GOOS, resp.Payload)
			}
		case "freebsd":
			if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:available")) {
				t.Fatalf("expected NEG-CAP-MODE available after %s on freebsd: %q", label, resp.Payload)
			}
			if !bytes.Contains(resp.Payload, []byte("|NEG-FS-READ:denied_as_expected")) {
				t.Fatalf("expected ambient NEG-FS-READ denial after %s on freebsd: %q", label, resp.Payload)
			}
			if !bytes.Contains(resp.Payload, []byte("|NEG-FS-PATH:available")) {
				t.Fatalf("expected NEG-FS-PATH available on freebsd via conferred dir fd after %s: %q", label, resp.Payload)
			}
		}
	}

	probe("roots-before-restart")
	if err := rt.WaitChild(authority.RoleApply); err != nil {
		t.Fatal(err)
	}
	if err := rt.RestartChild(ctx, authority.RoleApply, authority.RoleAuth, bin); err != nil {
		t.Fatal(err)
	}
	probe("roots-after-restart")
	if err := rt.WaitChild(authority.RoleApply); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildAuthAccept(t *testing.T) {
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
			Role:     authority.RolePlan,
			Confer:   []authority.Capability{authority.CapCanonicalManifests, authority.CapPlanOutput},
			IPCPeers: []authority.ProcessRole{authority.RoleAuth},
		},
		{
			Role: authority.RoleAuth,
			Confer: []authority.Capability{
				authority.CapIdentityHandle, authority.CapSessionKeyDerive, authority.CapAuthorizationPolicy,
			},
			IPCPeers: []authority.ProcessRole{authority.RolePlan},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x6c}, 32)
	var nonce [16]byte
	nonce[2] = 9
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleAuth, authority.RolePlan, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RolePlan, authority.RoleAuth)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("auth"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:auth|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-AUTH-ACCEPT:denied_as_expected")) {
		t.Fatalf("missing NEG-AUTH-ACCEPT in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-AUTH-CONTENTS:denied_as_expected")) {
		t.Fatalf("missing NEG-AUTH-CONTENTS in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-AUTH-PUB:denied_as_expected")) {
		t.Fatalf("missing NEG-AUTH-PUB in %q", resp.Payload)
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd":
		if !bytes.Contains(resp.Payload, []byte("|NEG-ROLE-NET:denied_as_expected")) {
			t.Fatalf("expected NEG-ROLE-NET denial on %s: %q", runtime.GOOS, resp.Payload)
		}
	}
	if err := rt.WaitChild(authority.RoleAuth); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildJournalMustNot(t *testing.T) {
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
			Role:     authority.RoleApply,
			Confer:   []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{authority.RoleJournal},
		},
		{
			Role: authority.RoleJournal,
			Confer: []authority.Capability{
				authority.CapJournalDescriptor, authority.CapAuthenticatedRecords,
			},
			IPCPeers: []authority.ProcessRole{authority.RoleApply},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x6d}, 32)
	var nonce [16]byte
	nonce[2] = 10
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleJournal, authority.RoleApply, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleApply, authority.RoleJournal)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("journal"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:journal|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-JOURNAL-NET:denied_as_expected")) {
		t.Fatalf("missing NEG-JOURNAL-NET in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-JOURNAL-POLICY:denied_as_expected")) {
		t.Fatalf("missing NEG-JOURNAL-POLICY in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-JOURNAL-MUTATE:denied_as_expected")) {
		t.Fatalf("missing NEG-JOURNAL-MUTATE in %q", resp.Payload)
	}
	if err := rt.WaitChild(authority.RoleJournal); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildAuditMustNot(t *testing.T) {
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
			Role: authority.RoleJournal,
			Confer: []authority.Capability{
				authority.CapJournalDescriptor, authority.CapAuthenticatedRecords,
			},
			IPCPeers: []authority.ProcessRole{authority.RoleAudit},
		},
		{
			Role: authority.RoleAudit,
			Confer: []authority.Capability{
				authority.CapReadonlyJournal, authority.CapRedactedEventSink,
			},
			IPCPeers: []authority.ProcessRole{authority.RoleJournal},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x6e}, 32)
	var nonce [16]byte
	nonce[2] = 11
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleAudit, authority.RoleJournal, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleJournal, authority.RoleAudit)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("audit"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:audit|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-AUDIT-DECIDE:denied_as_expected")) {
		t.Fatalf("missing NEG-AUDIT-DECIDE in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-AUDIT-ARCHIVES:denied_as_expected")) {
		t.Fatalf("missing NEG-AUDIT-ARCHIVES in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-AUDIT-SECRETS:denied_as_expected")) {
		t.Fatalf("missing NEG-AUDIT-SECRETS in %q", resp.Payload)
	}
	if err := rt.WaitChild(authority.RoleAudit); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildNetMustNot(t *testing.T) {
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
			Role:     authority.RoleParser,
			Confer:   []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{authority.RoleNet},
		},
		{
			Role:     authority.RoleNet,
			Confer:   []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{authority.RoleParser},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x6f}, 32)
	var nonce [16]byte
	nonce[2] = 12
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleNet, authority.RoleParser, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleParser, authority.RoleNet)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("net"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:net|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-NET-ARCHIVE:denied_as_expected")) {
		t.Fatalf("missing NEG-NET-ARCHIVE in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-NET-KEYS:denied_as_expected")) {
		t.Fatalf("missing NEG-NET-KEYS in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-NET-JOURNAL:denied_as_expected")) {
		t.Fatalf("missing NEG-NET-JOURNAL in %q", resp.Payload)
	}
	if err := rt.WaitChild(authority.RoleNet); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildPlanMustNot(t *testing.T) {
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
			Role: authority.RoleAuth,
			Confer: []authority.Capability{
				authority.CapIdentityHandle, authority.CapSessionKeyDerive, authority.CapAuthorizationPolicy,
			},
			IPCPeers: []authority.ProcessRole{authority.RolePlan},
		},
		{
			Role:     authority.RolePlan,
			Confer:   []authority.Capability{authority.CapCanonicalManifests, authority.CapPlanOutput},
			IPCPeers: []authority.ProcessRole{authority.RoleAuth},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x70}, 32)
	var nonce [16]byte
	nonce[2] = 13
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RolePlan, authority.RoleAuth, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleAuth, authority.RolePlan)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("plan"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:plan|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-PLAN-WRITE:denied_as_expected")) {
		t.Fatalf("missing NEG-PLAN-WRITE in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-PLAN-KEYS:denied_as_expected")) {
		t.Fatalf("missing NEG-PLAN-KEYS in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-PLAN-NET:denied_as_expected")) {
		t.Fatalf("missing NEG-PLAN-NET in %q", resp.Payload)
	}
	if err := rt.WaitChild(authority.RolePlan); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStartChildSupervisorMustNot(t *testing.T) {
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
			Role: authority.RoleAudit,
			Confer: []authority.Capability{
				authority.CapReadonlyJournal, authority.CapRedactedEventSink,
			},
			IPCPeers: []authority.ProcessRole{authority.RoleSupervisor},
		},
		{
			Role: authority.RoleSupervisor,
			Confer: []authority.Capability{
				authority.CapChildLifecycle, authority.CapPreopenedIPC, authority.CapPolicyIdentity,
			},
			IPCPeers: []authority.ProcessRole{authority.RoleAudit},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x71}, 32)
	var nonce [16]byte
	nonce[2] = 14
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.StartChild(ctx, authority.RoleSupervisor, authority.RoleAudit, bin); err != nil {
		t.Fatal(err)
	}

	parent, err := rt.Fabric.Endpoint(authority.RoleAudit, authority.RoleSupervisor)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("supervisor"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:supervisor|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-SUP-PARSER:denied_as_expected")) {
		t.Fatalf("missing NEG-SUP-PARSER in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-SUP-TRAVERSE:denied_as_expected")) {
		t.Fatalf("missing NEG-SUP-TRAVERSE in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-SUP-KEYS:denied_as_expected")) {
		t.Fatalf("missing NEG-SUP-KEYS in %q", resp.Payload)
	}
	if err := rt.WaitChild(authority.RoleSupervisor); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRestartPairIPC(t *testing.T) {
	// M2m: dual-live StartPair/RestartPair on default SCM key-channel path.
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
	if rt.KeyViaExtraFiles {
		t.Fatal("expected default SCM path (KeyViaExtraFiles=false)")
	}

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

func TestRuntimeRestartOneIPC(t *testing.T) {
	// M2n: kill one dual-live child; rebind peer FD into survivor; PID unchanged.
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
	key := bytes.Repeat([]byte{0x6c}, 32)
	var nonce [16]byte
	nonce[2] = 9
	rt, err := supervisor.OpenRuntime(p, key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	rt.PairHold = true

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := rt.StartPair(ctx, authority.RoleParser, authority.RoleNet, authority.RoleParser, bin); err != nil {
		t.Fatal(err)
	}
	live := rt.Children[authority.RoleNet]
	if live == nil || live.Cmd == nil || live.Cmd.Process == nil {
		t.Fatal("missing live net child")
	}
	livePID := live.Cmd.Process.Pid

	if err := rt.WaitPairHoldReady([]authority.ProcessRole{
		authority.RoleParser, authority.RoleNet,
	}, 10*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := rt.RestartOne(ctx, authority.RoleParser, authority.RoleNet, authority.RoleParser, bin); err != nil {
		t.Fatal(err)
	}
	if rt.Children[authority.RoleNet].Cmd.Process.Pid != livePID {
		t.Fatalf("live PID changed: got %d want %d", rt.Children[authority.RoleNet].Cmd.Process.Pid, livePID)
	}
	if err := rt.WaitChild(authority.RoleParser); err != nil {
		t.Fatal(err)
	}
	if err := rt.WaitChild(authority.RoleNet); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRestartPairExtraFiles(t *testing.T) {
	// Legacy KeyViaExtraFiles dual-live path remains supported.
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
	key := bytes.Repeat([]byte{0x6b}, 32)
	var nonce [16]byte
	nonce[2] = 8
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
}
