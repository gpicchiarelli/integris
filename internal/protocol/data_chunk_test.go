package protocol_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestDataChunkRoundTrip(t *testing.T) {
	body, err := protocol.EncodeDataChunkBody(1024, []byte("chunk-payload"))
	if err != nil {
		t.Fatal(err)
	}
	off, data, err := protocol.ParseDataChunkBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if off != 1024 || string(data) != "chunk-payload" {
		t.Fatalf("off=%d data=%q", off, data)
	}
}

func TestDataChunkRefuse(t *testing.T) {
	if _, err := protocol.EncodeDataChunkBody(0, make([]byte, protocol.MaxDataChunkBytes+1)); err == nil {
		t.Fatal("expected oversize encode refuse")
	}
	body, err := protocol.EncodeDataChunkBody(0, []byte("ab"))
	if err != nil {
		t.Fatal(err)
	}
	body[8] = 0xFF // corrupt declared length
	if _, _, err := protocol.ParseDataChunkBody(body); err == nil {
		t.Fatal("expected length mismatch")
	}
	if _, _, err := protocol.ParseDataChunkBody([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected truncated refuse")
	}
}

func bringDriversActive(t *testing.T, enc, dec *protocol.Driver) {
	t.Helper()
	for _, typ := range []protocol.MessageType{
		protocol.TypeNegotiateOffer, protocol.TypePeerAuth,
		protocol.TypeArchiveAuth, protocol.TypeActivate,
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
		if _, err := dec.DecodeAndHandle(raw); err != nil {
			t.Fatal(err)
		}
		if _, err := enc.DecodeAndHandle(raw); err != nil {
			t.Fatal(err)
		}
	}
	if enc.Session.State != session.StateActive || dec.Session.State != session.StateActive {
		t.Fatalf("enc=%s dec=%s", enc.Session.State, dec.Session.State)
	}
}

func TestDriverChunkedDataTransfer(t *testing.T) {
	mac := []byte("0123456789abcdef")
	var sid [16]byte
	sid[0] = 0x41
	alice := protocol.NewDriver([]session.Version{2, 3}, sid, mac, true)
	bob := protocol.NewDriver([]session.Version{2, 3}, sid, mac, true)
	alice.TrackDataChunks = true
	bob.TrackDataChunks = true
	bringDriversActive(t, alice, bob)

	raw, err := alice.EncodeDataChunk([]byte("hello "))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bob.LastPlaintext, []byte("hello ")) {
		t.Fatalf("%q", bob.LastPlaintext)
	}
	if bob.NextDataOffset != 6 || alice.NextSendOffset != 6 {
		t.Fatalf("bob=%d alice=%d", bob.NextDataOffset, alice.NextSendOffset)
	}

	raw, err = alice.EncodeDataChunk([]byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if bob.NextDataOffset != 11 {
		t.Fatalf("offset=%d", bob.NextDataOffset)
	}
}

func TestDriverChunkedDataRefuseGapReplay(t *testing.T) {
	mac := []byte("0123456789abcdef")
	var sid [16]byte
	sid[0] = 0x42
	alice := protocol.NewDriver([]session.Version{2, 3}, sid, mac, true)
	bob := protocol.NewDriver([]session.Version{2, 3}, sid, mac, true)
	alice.TrackDataChunks = true
	bob.TrackDataChunks = true
	bringDriversActive(t, alice, bob)

	raw, err := alice.EncodeDataChunk([]byte("aa"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}

	gap, err := protocol.EncodeDataChunkBody(4, []byte("xx"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = alice.EncodeFrame(protocol.TypeData, gap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err == nil {
		t.Fatal("expected gap refuse")
	}

	alice = protocol.NewDriver([]session.Version{2, 3}, sid, mac, true)
	bob = protocol.NewDriver([]session.Version{2, 3}, sid, mac, true)
	alice.TrackDataChunks = true
	bob.TrackDataChunks = true
	bringDriversActive(t, alice, bob)
	raw, err = alice.EncodeDataChunk([]byte("aa"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	replay, err := protocol.EncodeDataChunkBody(0, []byte("aa"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = alice.EncodeFrame(protocol.TypeData, replay)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err == nil {
		t.Fatal("expected replay refuse")
	}
}
