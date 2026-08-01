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
	// Control-plane types map to session steps; bodies are opaque for M1.
	s := session.New([]session.Version{2, 3})
	steps := []protocol.MessageType{
		protocol.TypeNegotiateOffer,
		protocol.TypeNegotiateAccept,
		protocol.TypePeerAuth,
		protocol.TypeArchiveAuth,
		protocol.TypeActivate,
	}
	var sid [16]byte
	sid[1] = 9
	key := []byte("0123456789abcdef")
	for i, typ := range steps {
		raw, err := protocol.Encode(protocol.Frame{
			Type: typ, Flags: protocol.FlagRequiresMAC, SessionID: sid,
			Sequence: uint64(i + 1), Body: []byte{byte(typ)},
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		f, err := protocol.Decode(raw, key, true)
		if err != nil {
			t.Fatal(err)
		}
		switch f.Type {
		case protocol.TypeNegotiateOffer, protocol.TypeNegotiateAccept:
			if s.State == session.StateNew {
				if err := s.Negotiate(); err != nil {
					t.Fatal(err)
				}
			}
		case protocol.TypePeerAuth:
			if err := s.Authenticate(); err != nil {
				t.Fatal(err)
			}
		case protocol.TypeArchiveAuth:
			if err := s.AuthorizeArchive(); err != nil {
				t.Fatal(err)
			}
		case protocol.TypeActivate:
			if err := s.Activate(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.Invariants(); err != nil || s.State != session.StateActive {
		t.Fatalf("state=%s err=%v", s.State, err)
	}
}

func asP(err error, target **protocol.Error) bool {
	if e, ok := err.(*protocol.Error); ok {
		*target = e
		return true
	}
	return false
}
