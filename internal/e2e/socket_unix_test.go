//go:build unix

package e2e_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

func TestM2SocketFabricAndConfine(t *testing.T) {
	rep := confine.Discover()
	found := false
	for _, f := range rep.Findings {
		if f.ID == "DISC-PREOPEN-FD" && f.Status == confine.StatusAvailable {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected preopen fd available: %+v", rep.Findings)
	}
	p, err := supervisor.MinimalRuntimePlan()
	if err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{0x44}, 32)
	var nonce [16]byte
	copy(nonce[:], []byte("sock-e2e-nonce!!"))
	set, err := supervisor.MaterializeLaunch(p, root, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := set.VerifyAll(root); err != nil {
		t.Fatal(err)
	}
	fab, err := supervisor.OpenSocketFabric(p, root, nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer fab.Close()
	frame, err := fab.Deliver(authority.RoleJournal, authority.RoleAudit, ipc.TypeRequest, []byte("event"))
	if err != nil {
		t.Fatal(err)
	}
	if string(frame.Payload) != "event" {
		t.Fatalf("%q", frame.Payload)
	}
}
