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
