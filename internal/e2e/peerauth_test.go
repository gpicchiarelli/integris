package e2e_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestM3PreludePeerAuthAndAEAD(t *testing.T) {
	var sid [16]byte
	copy(sid[:], []byte("peer-auth-sess01"))
	mac := bytes.Repeat([]byte{0xcd}, 16)
	root := bytes.Repeat([]byte{0xef}, 32)
	suites := []string{crypto.SuiteIDAEAD}
	authKey, err := crypto.PeerAuthKey(root, sid)
	if err != nil {
		t.Fatal(err)
	}

	alice := protocol.NewDriverWithSuites([]session.Version{3, 2}, suites, sid, mac, true)
	bob := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
	alice.AuthKey, bob.AuthKey = authKey, authKey
	alice.AuthDir, bob.AuthDir = "i2r", "i2r"

	// Negotiate
	raw, err := alice.EncodeFrame(protocol.TypeNegotiateOffer, []byte{3, 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}

	// Peer auth proof
	raw, err = alice.EncodePeerAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}

	for _, typ := range []protocol.MessageType{protocol.TypeArchiveAuth, protocol.TypeActivate} {
		raw, err = alice.EncodeFrame(typ, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bob.DecodeAndHandle(raw); err != nil {
			t.Fatal(err)
		}
		if _, err := alice.DecodeAndHandle(raw); err != nil {
			t.Fatal(err)
		}
	}

	if err := alice.InstallTrafficKey(root); err != nil {
		t.Fatal(err)
	}
	if err := bob.InstallTrafficKey(root); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(alice.AEADKey, bob.AEADKey) {
		t.Fatal("traffic keys diverged")
	}

	raw, err = alice.EncodeFrame(protocol.TypeData, []byte("authenticated"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if string(bob.LastPlaintext) != "authenticated" {
		t.Fatalf("%q", bob.LastPlaintext)
	}
}
