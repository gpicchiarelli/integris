package e2e_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

func TestM2PreludeLaunchFabric(t *testing.T) {
	p, err := supervisor.MinimalRuntimePlan()
	if err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{0x22}, 32)
	var nonce [16]byte
	copy(nonce[:], []byte("launch-fabric-n0"))
	set, err := supervisor.MaterializeLaunch(p, root, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.VerifyAll(root); err != nil {
		t.Fatal(err)
	}
	fab, err := supervisor.OpenFabric(p, root, nonce)
	if err != nil {
		t.Fatal(err)
	}
	var netLaunch *supervisor.ChildLaunch
	for i := range set.Children {
		if set.Children[i].Role == authority.RoleNet {
			netLaunch = &set.Children[i]
			break
		}
	}
	if netLaunch == nil {
		t.Fatal("missing net")
	}
	ch, err := fab.Channel(authority.RoleNet, authority.RoleParser)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.MACKey) == 0 {
		t.Fatal("expected MAC key")
	}
	found := false
	for _, pk := range netLaunch.Peers {
		if pk.Peer == authority.RoleParser {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("net launch missing parser peer key id")
	}
	if _, err := fab.Deliver(authority.RoleNet, authority.RoleParser, ipc.TypeRequest, []byte("ping")); err != nil {
		t.Fatal(err)
	}
}
