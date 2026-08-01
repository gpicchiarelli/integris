package protocol_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestRoundTripEmptyBody(t *testing.T) {
	var sid [16]byte
	sid[0] = 1
	raw, err := protocol.Encode(protocol.Frame{
		Type: protocol.TypeClose, SessionID: sid, Sequence: 1,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := protocol.Decode(raw, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeClose || f.Sequence != 1 || len(f.Body) != 0 {
		t.Fatalf("%+v", f)
	}
}

func TestMACRequired(t *testing.T) {
	key := []byte("0123456789abcdef")
	var sid [16]byte
	raw, err := protocol.Encode(protocol.Frame{
		Type: protocol.TypeActivate, Flags: protocol.FlagRequiresMAC,
		SessionID: sid, Sequence: 2, Body: []byte("ok"),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.Decode(raw, key, true); err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	_, err = protocol.Decode(raw, key, true)
	var e *protocol.Error
	if err == nil || !asP(err, &e) || e.Code != "mac" {
		t.Fatalf("got %v", err)
	}
}

func TestRejectOversizeBeforeAlloc(t *testing.T) {
	body := make([]byte, protocol.MaxBodyBytes+1)
	_, err := protocol.Encode(protocol.Frame{Type: protocol.TypeData, Body: body}, nil)
	if err == nil {
		t.Fatal("expected limit")
	}
}

func TestSessionDriveWithFrames(t *testing.T) {
	var sid [16]byte
	sid[1] = 9
	key := []byte("0123456789abcdef")
	d := protocol.NewDriver([]session.Version{2, 3}, sid, key, true)
	enc := protocol.NewDriver([]session.Version{2, 3}, sid, key, true)
	for _, typ := range []protocol.MessageType{
		protocol.TypeNegotiateOffer,
		protocol.TypeNegotiateAccept,
		protocol.TypePeerAuth,
		protocol.TypeArchiveAuth,
		protocol.TypeActivate,
	} {
		var raw []byte
		var err error
		if typ == protocol.TypeNegotiateOffer {
			raw, err = enc.EncodeNegotiateOffer([]session.Version{2, 3})
		} else {
			raw, err = enc.EncodeFrame(typ, nil)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.DecodeAndHandle(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Session.Invariants(); err != nil || d.Session.State != session.StateActive {
		t.Fatalf("state=%s err=%v", d.Session.State, err)
	}
}

func asP(err error, target **protocol.Error) bool {
	if e, ok := err.(*protocol.Error); ok {
		*target = e
		return true
	}
	return false
}
