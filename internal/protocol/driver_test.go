package protocol_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestDriverHappyPath(t *testing.T) {
	var sid [16]byte
	sid[0] = 7
	key := []byte("0123456789abcdef")
	tr := crypto.NewTranscript()
	d := protocol.NewDriver([]session.Version{2, 3}, sid, key, true)
	d.Session.Transcript = tr

	steps := []struct {
		typ  protocol.MessageType
		body []byte
	}{
		{protocol.TypeNegotiateOffer, []byte{2, 3}},
		{protocol.TypePeerAuth, nil},
		{protocol.TypeArchiveAuth, nil},
		{protocol.TypeActivate, nil},
		{protocol.TypeData, []byte("x")},
		{protocol.TypeClose, nil},
	}
	// Separate encode driver so sequences stay aligned on one peer view.
	enc := protocol.NewDriver([]session.Version{2, 3}, sid, key, true)
	for _, st := range steps {
		raw, err := enc.EncodeFrame(st.typ, st.body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.DecodeAndHandle(raw); err != nil {
			t.Fatalf("%v: %v", st.typ, err)
		}
	}
	if d.Session.State != session.StateClosed {
		t.Fatalf("state=%s", d.Session.State)
	}
	if tr.Digest() == (crypto.NewTranscript().Digest()) {
		t.Fatal("expected non-empty transcript")
	}
}

func TestDriverRejectBadSequence(t *testing.T) {
	var sid [16]byte
	d := protocol.NewDriver([]session.Version{2}, sid, nil, false)
	raw, err := protocol.Encode(protocol.Frame{
		Type: protocol.TypeNegotiateOffer, SessionID: sid, Sequence: 2, Body: []byte{2},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DecodeAndHandle(raw)
	var e *protocol.Error
	if err == nil || !asP(err, &e) || e.Code != "sequence" {
		t.Fatalf("got %v", err)
	}
}
