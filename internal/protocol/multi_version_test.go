package protocol_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

// TestMultiVersionNegotiateHappyPath consolidates M3 multi-version / suite
// preference success paths on the Driver wire (companion to hostile_peer_test).
func TestMultiVersionNegotiateHappyPath(t *testing.T) {
	mac := []byte("0123456789abcdef")
	root := bytes.Repeat([]byte{0xcd}, 32)
	aead := crypto.SuiteIDAEAD

	type tc struct {
		name       string
		aliceVers  []session.Version
		bobSuites  []string // suites bob advertises locally before wire; wire overwrites from alice offer
		offerVers  []session.Version
		offerSuite []string
		wantVers   session.Version
		wantSuite  string
		fullPath   bool // continue through Activate + TypeData
	}

	cases := []tc{
		{
			name:       "prefer_v3_offer_order_high_first",
			aliceVers:  []session.Version{3, 2},
			bobSuites:  []string{aead},
			offerVers:  []session.Version{3, 2},
			offerSuite: []string{aead},
			wantVers:   3,
			wantSuite:  aead,
			fullPath:   true,
		},
		{
			name:       "prefer_v3_offer_order_low_first",
			aliceVers:  []session.Version{2, 3},
			bobSuites:  []string{aead},
			offerVers:  []session.Version{2, 3},
			offerSuite: []string{aead},
			wantVers:   3,
			wantSuite:  aead,
		},
		{
			name:       "intersect_v2_only",
			aliceVers:  []session.Version{2},
			bobSuites:  []string{aead},
			offerVers:  []session.Version{2},
			offerSuite: []string{aead},
			wantVers:   2,
			wantSuite:  aead,
		},
		{
			name:       "intersect_v3_only",
			aliceVers:  []session.Version{3},
			bobSuites:  []string{aead},
			offerVers:  []session.Version{3},
			offerSuite: []string{aead},
			wantVers:   3,
			wantSuite:  aead,
		},
		{
			name:       "suite_intersection_skips_unknown",
			aliceVers:  []session.Version{3, 2},
			bobSuites:  []string{aead},
			offerVers:  []session.Version{3, 2},
			offerSuite: []string{"peer-invented-suite", aead},
			wantVers:   3,
			wantSuite:  aead,
		},
		{
			name:       "bob_constructor_narrower_than_wire_offer",
			aliceVers:  []session.Version{3, 2},
			bobSuites:  []string{aead},
			offerVers:  []session.Version{3, 2},
			offerSuite: []string{aead},
			wantVers:   3,
			wantSuite:  aead,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var sid [16]byte
			sid[0] = byte(len(c.name))
			alice := protocol.NewDriverWithSuites(c.aliceVers, c.offerSuite, sid, mac, true)
			// Bob starts with a minimal local allow-list; wire offer replaces Offered.
			bob := protocol.NewDriverWithSuites([]session.Version{2}, c.bobSuites, sid, mac, true)

			offer, err := alice.EncodeNegotiateOffer(c.offerVers)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bob.DecodeAndHandle(offer); err != nil {
				t.Fatal(err)
			}
			if bob.Session.Selected != c.wantVers || bob.Session.SelectedSuite != c.wantSuite {
				t.Fatalf("bob selected=%d suite=%q want %d %q", bob.Session.Selected, bob.Session.SelectedSuite, c.wantVers, c.wantSuite)
			}

			accept, err := bob.EncodeNegotiateAccept()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := alice.DecodeAndHandle(accept); err != nil {
				t.Fatal(err)
			}
			if alice.Session.State != session.StateNegotiated || bob.Session.State != session.StateNegotiated {
				t.Fatalf("states alice=%s bob=%s", alice.Session.State, bob.Session.State)
			}
			if alice.Session.Selected != c.wantVers || alice.Session.SelectedSuite != c.wantSuite {
				t.Fatalf("alice selected=%d suite=%q want %d %q", alice.Session.Selected, alice.Session.SelectedSuite, c.wantVers, c.wantSuite)
			}
			if alice.Session.Selected != bob.Session.Selected || alice.Session.SelectedSuite != bob.Session.SelectedSuite {
				t.Fatalf("peers diverged: alice=%d/%q bob=%d/%q",
					alice.Session.Selected, alice.Session.SelectedSuite,
					bob.Session.Selected, bob.Session.SelectedSuite)
			}

			if !c.fullPath {
				return
			}
			driveToData(t, alice, bob, mac, root)
		})
	}
}

func driveToData(t *testing.T, alice, bob *protocol.Driver, mac, root []byte) {
	t.Helper()
	authKey, err := crypto.PeerAuthKey(root, alice.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	archKey, err := crypto.ArchiveAuthKey(root, alice.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	alice.AuthKey, bob.AuthKey = authKey, authKey
	alice.ArchiveKey, bob.ArchiveKey = archKey, archKey
	alice.AuthDir, bob.AuthDir = "i2r", "r2i"

	raw, err := alice.EncodePeerAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	raw, err = bob.EncodePeerAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}

	raw, err = alice.EncodeArchiveAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if alice.Session.State != session.StateArchiveAuthorized || bob.Session.State != session.StateArchiveAuthorized {
		t.Fatalf("archive states alice=%s bob=%s", alice.Session.State, bob.Session.State)
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

	raw, err = alice.EncodeFrame(protocol.TypeData, []byte("multi-version-ok"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if string(bob.LastPlaintext) != "multi-version-ok" {
		t.Fatalf("%q", bob.LastPlaintext)
	}
	_ = mac
}
