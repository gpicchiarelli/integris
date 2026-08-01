//go:build unix

package supervisor_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

func TestOpenSocketFabricDeliver(t *testing.T) {
	p, err := supervisor.MinimalRuntimePlan()
	if err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{0x33}, 32)
	var nonce [16]byte
	nonce[0] = 7
	fab, err := supervisor.OpenSocketFabric(p, root, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer fab.Close()
	if fab.PairCount() == 0 {
		t.Fatal("no pairs")
	}
	frame, err := fab.Deliver(authority.RoleAuth, authority.RolePlan, ipc.TypeRequest, []byte("authorize?"))
	if err != nil {
		t.Fatal(err)
	}
	if string(frame.Payload) != "authorize?" || frame.Sender != authority.RoleAuth {
		t.Fatalf("%+v", frame)
	}
}

func TestSocketFabricReplacePair(t *testing.T) {
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
	root := bytes.Repeat([]byte{0x34}, 32)
	var nonce [16]byte
	nonce[0] = 8
	fab, err := supervisor.OpenSocketFabric(p, root, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer fab.Close()
	if _, err := fab.Deliver(authority.RoleNet, authority.RoleParser, ipc.TypeRequest, []byte("before")); err != nil {
		t.Fatal(err)
	}
	if err := fab.ReplacePair(authority.RoleParser, authority.RoleNet, root); err != nil {
		t.Fatal(err)
	}
	frame, err := fab.Deliver(authority.RoleNet, authority.RoleParser, ipc.TypeRequest, []byte("after"))
	if err != nil {
		t.Fatal(err)
	}
	if string(frame.Payload) != "after" {
		t.Fatalf("%+v", frame)
	}
}
