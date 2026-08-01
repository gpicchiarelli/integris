package protocol_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestDriverTrafficKeyFromTranscript(t *testing.T) {
	var sid [16]byte
	sid[0] = 5
	mac := []byte("0123456789abcdef")
	root := bytes.Repeat([]byte{0xab}, 32)
	suites := []string{crypto.SuiteIDAEAD}

	enc := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
	dec := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)

	for _, typ := range []protocol.MessageType{
		protocol.TypeNegotiateOffer, protocol.TypePeerAuth,
		protocol.TypeArchiveAuth, protocol.TypeActivate,
	} {
		var body []byte
		if typ == protocol.TypeNegotiateOffer {
			body = []byte{2, 3}
		}
		raw, err := enc.EncodeFrame(typ, body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dec.DecodeAndHandle(raw); err != nil {
			t.Fatal(err)
		}
		// Keep encoder session in sync for Activate path.
		if _, err := enc.DecodeAndHandle(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := enc.InstallTrafficKey(root); err != nil {
		t.Fatal(err)
	}
	if err := dec.InstallTrafficKey(root); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc.AEADKey, dec.AEADKey) {
		t.Fatal("peers derived different traffic keys")
	}

	raw, err := enc.EncodeFrame(protocol.TypeData, []byte("bound-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dec.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if string(dec.LastPlaintext) != "bound-secret" {
		t.Fatalf("%q", dec.LastPlaintext)
	}
}
