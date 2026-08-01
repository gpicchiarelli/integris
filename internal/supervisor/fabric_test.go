package supervisor_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

func TestOpenFabricMinimal(t *testing.T) {
	p, err := supervisor.MinimalRuntimePlan()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateIPCGraph(); err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{7}, 32)
	var nonce [16]byte
	nonce[0] = 1
	fab, err := supervisor.OpenFabric(p, root, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if fab.PairCount() == 0 {
		t.Fatal("expected pairs")
	}
	frame, err := fab.Deliver(authority.RoleNet, authority.RoleParser, ipc.TypeRequest, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if string(frame.Payload) != "hello" || frame.Sender != authority.RoleNet {
		t.Fatalf("%+v", frame)
	}
	if _, err := fab.Deliver(authority.RoleNet, authority.RoleParser, ipc.TypeResponse, []byte("ok")); err != nil {
		t.Fatal(err)
	}
}

func TestRejectNonMutualIPC(t *testing.T) {
	p, err := supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:     authority.RoleNet,
			Confer:   []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{authority.RoleParser},
		},
		{
			Role:     authority.RoleParser,
			Confer:   []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateIPCGraph(); err == nil {
		t.Fatal("expected non-mutual failure")
	}
}
