package ipc_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/ipc"
)

func TestStreamRoundTrip(t *testing.T) {
	ch := ipc.NewChannel(authority.RoleNet, authority.RoleParser, [16]byte{1})
	raw, err := ch.Encode(ipc.TypeRequest, []byte("stream"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ipc.WriteFrame(&buf, raw); err != nil {
		t.Fatal(err)
	}
	got, err := ipc.ReadFrame(&buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer := ipc.NewChannel(authority.RoleParser, authority.RoleNet, [16]byte{1})
	f, err := peer.Decode(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Payload) != "stream" {
		t.Fatalf("%q", f.Payload)
	}
}

func TestStreamRejectOversize(t *testing.T) {
	var buf bytes.Buffer
	huge := make([]byte, ipc.MaxFrameBytes+ipc.HeaderBytes+ipc.MACBytes+1)
	if err := ipc.WriteFrame(&buf, huge); err == nil {
		t.Fatal("expected limit")
	}
}
