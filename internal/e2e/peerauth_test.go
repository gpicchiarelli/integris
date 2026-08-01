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
	archKey, err := crypto.ArchiveAuthKey(root, sid)
	if err != nil {
		t.Fatal(err)
	}

	alice := protocol.NewDriverWithSuites([]session.Version{3, 2}, suites, sid, mac, true)
	bob := protocol.NewDriverWithSuites([]session.Version{2, 3}, suites, sid, mac, true)
	alice.AuthKey, bob.AuthKey = authKey, authKey
	alice.ArchiveKey, bob.ArchiveKey = archKey, archKey
	alice.AuthDir, bob.AuthDir = "i2r", "r2i"

	// Negotiate: alice applies locally; bob via inbound wire offer (independent seqs).
	if err := alice.Session.Negotiate(); err != nil {
		t.Fatal(err)
	}
	raw, err := alice.EncodeNegotiateOffer([]session.Version{3, 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}

	raw, err = alice.EncodePeerAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if alice.Session.State != session.StateNegotiated || bob.Session.State != session.StateNegotiated {
		t.Fatalf("one-sided auth advanced early: alice=%s bob=%s", alice.Session.State, bob.Session.State)
	}

	raw, err = bob.EncodePeerAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if alice.Session.State != session.StatePeerAuthenticated || bob.Session.State != session.StatePeerAuthenticated {
		t.Fatalf("mutual auth incomplete: alice=%s bob=%s", alice.Session.State, bob.Session.State)
	}

	raw, err = alice.EncodeArchiveAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if alice.Session.State != session.StateArchiveAuthorized || bob.Session.State != session.StateArchiveAuthorized {
		t.Fatalf("archive auth incomplete: alice=%s bob=%s", alice.Session.State, bob.Session.State)
	}

	if err := alice.Session.Activate(); err != nil {
		t.Fatal(err)
	}
	raw, err = alice.EncodeFrame(protocol.TypeActivate, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
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
