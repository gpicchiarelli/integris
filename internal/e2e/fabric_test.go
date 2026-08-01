package e2e_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/ipc"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

func TestM2PreludePlanFabricMAC(t *testing.T) {
	tr := crypto.NewTranscript()
	if err := tr.Append("suite", []byte("integris-ipc-mac-v1")); err != nil {
		t.Fatal(err)
	}
	plan, err := supervisor.MinimalRuntimePlan()
	if err != nil {
		t.Fatal(err)
	}
	root := bytes.Repeat([]byte{0x11}, 32)
	var nonce [16]byte
	copy(nonce[:], []byte("e2e-fabric-nonce"))
	if err := tr.Append("nonce", nonce[:]); err != nil {
		t.Fatal(err)
	}
	fab, err := supervisor.OpenFabric(plan, root, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if fab.PairCount() < 10 {
		t.Fatalf("pairs=%d", fab.PairCount())
	}
	frame, err := fab.Deliver(authority.RoleApply, authority.RoleJournal, ipc.TypeRequest, []byte("append-intent"))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != ipc.TypeRequest || string(frame.Payload) != "append-intent" {
		t.Fatalf("%+v", frame)
	}
	// Tamper: re-encode with wrong key must fail decode on peer.
	badKey := bytes.Repeat([]byte{0x99}, 32)
	bad, err := ipc.NewAuthenticatedChannel(authority.RoleApply, authority.RoleJournal, nonce, badKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := bad.Encode(ipc.TypeRequest, []byte("evil"))
	if err != nil {
		t.Fatal(err)
	}
	dst, err := fab.Channel(authority.RoleJournal, authority.RoleApply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dst.Decode(raw); err == nil {
		t.Fatal("expected MAC failure")
	}
	_ = tr.Digest()
}
