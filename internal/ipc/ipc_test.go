package ipc_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/ipc"
)

func TestRoundTrip(t *testing.T) {
	var nonce [16]byte
	nonce[0] = 7
	send := ipc.NewChannel(authority.RolePlan, authority.RoleApply, nonce)
	recv := ipc.NewChannel(authority.RoleApply, authority.RolePlan, nonce)
	raw, err := send.Encode(ipc.TypeRequest, []byte("plan-digest"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := recv.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.Sequence != 1 || string(f.Payload) != "plan-digest" {
		t.Fatalf("%+v", f)
	}
}

func TestRejectRoleMismatch(t *testing.T) {
	var nonce [16]byte
	send := ipc.NewChannel(authority.RoleNet, authority.RoleAuth, nonce)
	recv := ipc.NewChannel(authority.RoleParser, authority.RoleNet, nonce) // wrong
	raw, err := send.Encode(ipc.TypeRequest, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = recv.Decode(raw)
	var e *ipc.Error
	if err == nil || !asIPC(err, &e) || e.Code != "role" || !e.Close {
		t.Fatalf("got %v", err)
	}
}

func TestRejectDuplicateSequence(t *testing.T) {
	var nonce [16]byte
	send := ipc.NewChannel(authority.RoleJournal, authority.RoleAudit, nonce)
	recv := ipc.NewChannel(authority.RoleAudit, authority.RoleJournal, nonce)
	raw, err := send.Encode(ipc.TypeRequest, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recv.Decode(raw); err != nil {
		t.Fatal(err)
	}
	_, err = recv.Decode(raw)
	var e *ipc.Error
	if err == nil || !asIPC(err, &e) || e.Code != "sequence" {
		t.Fatalf("got %v", err)
	}
}

func TestCloseFrame(t *testing.T) {
	var nonce [16]byte
	send := ipc.NewChannel(authority.RoleSupervisor, authority.RoleNet, nonce)
	raw, err := send.Encode(ipc.TypeClose, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !send.Closed {
		t.Fatal("sender should close")
	}
	recv := ipc.NewChannel(authority.RoleNet, authority.RoleSupervisor, nonce)
	if _, err := recv.Decode(raw); err != nil {
		t.Fatal(err)
	}
	if !recv.Closed {
		t.Fatal("receiver should close")
	}
}

func TestAuthenticatedRoundTrip(t *testing.T) {
	var nonce [16]byte
	nonce[0] = 9
	key := []byte("0123456789abcdef")
	send, err := ipc.NewAuthenticatedChannel(authority.RolePlan, authority.RoleApply, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := ipc.NewAuthenticatedChannel(authority.RoleApply, authority.RolePlan, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := send.Encode(ipc.TypeRequest, []byte("auth-payload"))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < ipc.HeaderBytes+ipc.MACBytes {
		t.Fatalf("short mac frame %d", len(raw))
	}
	f, err := recv.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Payload) != "auth-payload" {
		t.Fatalf("%+v", f)
	}
}

func TestRejectTamperedMAC(t *testing.T) {
	var nonce [16]byte
	key := []byte("0123456789abcdef")
	send, err := ipc.NewAuthenticatedChannel(authority.RoleJournal, authority.RoleAudit, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := ipc.NewAuthenticatedChannel(authority.RoleAudit, authority.RoleJournal, nonce, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := send.Encode(ipc.TypeRequest, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	_, err = recv.Decode(raw)
	var e *ipc.Error
	if err == nil || !asIPC(err, &e) || e.Code != "mac" || !e.Close {
		t.Fatalf("got %v", err)
	}
}

func asIPC(err error, target **ipc.Error) bool {
	if e, ok := err.(*ipc.Error); ok {
		*target = e
		return true
	}
	return false
}
