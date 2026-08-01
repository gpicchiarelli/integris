package e2e_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestM3PreludeSuiteAEAD(t *testing.T) {
	var sid [16]byte
	copy(sid[:], []byte("e2e-session-id!!"))
	mac := bytes.Repeat([]byte{0xcd}, 16)
	root := bytes.Repeat([]byte{0xef}, 32)
	suites := []string{crypto.SuiteIDAEAD}

	alice := protocol.NewDriverWithSuites([]session.Version{3, 2}, suites, sid, mac, true)
	bob := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)

	raw, err := alice.EncodeNegotiateOffer([]session.Version{3, 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []protocol.MessageType{
		protocol.TypePeerAuth, protocol.TypeArchiveAuth, protocol.TypeActivate,
	} {
		raw, err := alice.EncodeFrame(typ, nil)
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
	if bob.Session.Selected != 3 || bob.Session.SelectedSuite != crypto.SuiteIDAEAD {
		t.Fatalf("selected=%d suite=%q", bob.Session.Selected, bob.Session.SelectedSuite)
	}
	if err := alice.InstallTrafficKey(root); err != nil {
		t.Fatal(err)
	}
	if err := bob.InstallTrafficKey(root); err != nil {
		t.Fatal(err)
	}
	raw, err = alice.EncodeFrame(protocol.TypeData, []byte("m3-prelude"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if string(bob.LastPlaintext) != "m3-prelude" {
		t.Fatalf("%q", bob.LastPlaintext)
	}
	if err := bob.Session.Invariants(); err != nil {
		t.Fatal(err)
	}
}
