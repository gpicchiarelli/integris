//go:build unix

package launcher_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

func TestRefuseUnsetMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := launcher.Start(ctx, launcher.Request{
		Executable: "/bin/true", Role: authority.RoleParser, Peer: authority.RoleNet,
		MACKey: bytes.Repeat([]byte{1}, 16), Socket: os.Stdin,
	})
	var e *launcher.Error
	if !errors.As(err, &e) || e.Code != "mode" {
		t.Fatalf("got %v", err)
	}
}

func TestRefuseBothModes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := launcher.Start(ctx, launcher.Request{
		Executable: "/bin/true", Role: authority.RoleParser, Peer: authority.RoleNet,
		MACKey: bytes.Repeat([]byte{1}, 16), Socket: os.Stdin,
		EngineeringMode: true, ReleaseMode: true,
	})
	var e *launcher.Error
	if !errors.As(err, &e) || e.Code != "mode" {
		t.Fatalf("got %v", err)
	}
}

func TestLaunchStubIPC(t *testing.T) {
	root, err := moduleRoot(t)
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
	keyRoot := bytes.Repeat([]byte{0x55}, 32)
	var nonce [16]byte
	nonce[1] = 2
	fab, err := supervisor.OpenSocketFabric(p, keyRoot, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer fab.Close()

	childEp, err := fab.Endpoint(authority.RoleParser, authority.RoleNet)
	if err != nil {
		t.Fatal(err)
	}
	sockFile, err := childEp.Conn.File()
	if err != nil {
		t.Fatal(err)
	}
	defer sockFile.Close()
	// Parent must not retain the child-side connection (avoid competing readers).
	_ = childEp.Conn.Close()
	childEp.Conn = nil

	macKey, err := crypto.ChannelMACKey(keyRoot, string(authority.RoleParser), string(authority.RoleNet))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := launcher.Start(ctx, launcher.Request{
		Executable:      bin,
		Role:            authority.RoleParser,
		Peer:            authority.RoleNet,
		Nonce:           nonce,
		MACKey:          macKey,
		Socket:          sockFile,
		EngineeringMode: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.KeyFD == nil || h.KeyChannel == nil {
		t.Fatal("expected KeyFD and KeyChannel for default SCM path")
	}
	if err := ipc.SendFDFile(h.KeyChannel, h.KeyFD); err != nil {
		t.Fatal(err)
	}
	_ = h.KeyFD.Close()
	h.KeyFD = nil
	_ = h.KeyChannel.Close()
	h.KeyChannel = nil

	parent, err := fab.Endpoint(authority.RoleNet, authority.RoleParser)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("ping"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:ping|")) {
		t.Fatalf("%q", resp.Payload)
	}
	for _, tok := range []string{"|NEG-CAP-MODE:", "|NEG-FS:", "|NEG-EXEC:", "|NEG-PTRACE:"} {
		if !bytes.Contains(resp.Payload, []byte(tok)) {
			t.Fatalf("missing %s in %q", tok, resp.Payload)
		}
	}
	switch runtime.GOOS {
	case "darwin", "linux", "openbsd":
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
		// Capsicum is fd-only today; ambient socket() remains possible (NEG-ROLE-NET gap).
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
	if !bytes.Contains(resp.Payload, []byte("|KEY:"+launcher.KeyTransportSCMRights)) {
		t.Fatalf("missing default scm key transport in %q", resp.Payload)
	}
	if err := h.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchStubIPCViaExtraFiles(t *testing.T) {
	root, err := moduleRoot(t)
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
	keyRoot := bytes.Repeat([]byte{0x57}, 32)
	var nonce [16]byte
	nonce[1] = 9
	fab, err := supervisor.OpenSocketFabric(p, keyRoot, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer fab.Close()

	childEp, err := fab.Endpoint(authority.RoleParser, authority.RoleNet)
	if err != nil {
		t.Fatal(err)
	}
	sockFile, err := childEp.Conn.File()
	if err != nil {
		t.Fatal(err)
	}
	defer sockFile.Close()
	_ = childEp.Conn.Close()
	childEp.Conn = nil

	macKey, err := crypto.ChannelMACKey(keyRoot, string(authority.RoleParser), string(authority.RoleNet))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := launcher.Start(ctx, launcher.Request{
		Executable:       bin,
		Role:             authority.RoleParser,
		Peer:             authority.RoleNet,
		Nonce:            nonce,
		MACKey:           macKey,
		Socket:           sockFile,
		EngineeringMode:  true,
		KeyViaExtraFiles: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.KeyFD != nil {
		t.Fatal("legacy ExtraFiles path must not return KeyFD")
	}

	parent, err := fab.Endpoint(authority.RoleNet, authority.RoleParser)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parent.Chan.Encode(ipc.TypeRequest, []byte("extra"))
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
	if !bytes.HasPrefix(resp.Payload, []byte("ack:extra|")) {
		t.Fatalf("%q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|NEG-CAP-MODE:")) || !bytes.Contains(resp.Payload, []byte("|NEG-FS:")) {
		t.Fatalf("missing NEG-CAP-MODE/NEG-FS in %q", resp.Payload)
	}
	if !bytes.Contains(resp.Payload, []byte("|KEY:"+launcher.KeyTransportAnonFile)) &&
		!bytes.Contains(resp.Payload, []byte("|KEY:"+launcher.KeyTransportMemfd)) {
		t.Fatalf("missing legacy key transport in %q", resp.Payload)
	}
	if err := h.Wait(); err != nil {
		t.Fatal(err)
	}
}

func moduleRoot(t *testing.T) (string, error) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// internal/launcher → repo root
	return filepath.Abs(filepath.Join(wd, "../.."))
}
