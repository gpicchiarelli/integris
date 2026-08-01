package protocol_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/protocol"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestNegotiateOfferBodyRoundTrip(t *testing.T) {
	vers := []session.Version{3, 2}
	suites := []string{crypto.SuiteIDAEAD, "other"}
	body, err := protocol.EncodeNegotiateOfferBody(vers, suites)
	if err != nil {
		t.Fatal(err)
	}
	gotV, gotS, err := protocol.ParseNegotiateOfferBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotV) != 2 || gotV[0] != 3 || gotV[1] != 2 {
		t.Fatalf("vers=%v", gotV)
	}
	if len(gotS) != 2 || gotS[0] != crypto.SuiteIDAEAD || gotS[1] != "other" {
		t.Fatalf("suites=%v", gotS)
	}
}

func TestNegotiateOfferBodyRejectsMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{0},
		{0, 0},
		{2, 3}, // truncated versions
		{1, 3, 2, 5, 'a', 'b'}, // truncated suite
	}
	for _, body := range cases {
		if _, _, err := protocol.ParseNegotiateOfferBody(body); err == nil {
			t.Fatalf("expected error for %v", body)
		}
	}
}

func TestDriverNegotiateOfferWireSuites(t *testing.T) {
	var sid [16]byte
	sid[0] = 9
	mac := []byte("0123456789abcdef")
	alice := protocol.NewDriverWithSuites([]session.Version{3, 2}, []string{crypto.SuiteIDAEAD}, sid, mac, true)
	bob := protocol.NewDriverWithSuites([]session.Version{2, 3}, []string{crypto.SuiteIDAEAD}, sid, mac, true)

	raw, err := alice.EncodeNegotiateOffer([]session.Version{3, 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.DecodeAndHandle(raw); err != nil {
		t.Fatal(err)
	}
	if bob.Session.Selected != 3 || bob.Session.SelectedSuite != crypto.SuiteIDAEAD {
		t.Fatalf("selected=%d suite=%q", bob.Session.Selected, bob.Session.SelectedSuite)
	}
	if len(bob.Session.OfferedSuites) != 1 || bob.Session.OfferedSuites[0] != crypto.SuiteIDAEAD {
		t.Fatalf("offered suites=%v", bob.Session.OfferedSuites)
	}
}

func TestDriverNegotiateOfferUnknownSuiteFails(t *testing.T) {
	var sid [16]byte
	mac := []byte("0123456789abcdef")
	bob := protocol.NewDriverWithSuites([]session.Version{2, 3}, []string{crypto.SuiteIDAEAD}, sid, mac, true)
	body, err := protocol.EncodeNegotiateOfferBody([]session.Version{2, 3}, []string{"unknown-suite-only"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := protocol.NewDriver([]session.Version{2}, sid, mac, true).EncodeFrame(protocol.TypeNegotiateOffer, body)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bob.DecodeAndHandle(raw)
	if err == nil {
		t.Fatal("expected suite negotiation failure")
	}
	if bob.Session.State != session.StateFailed {
		t.Fatalf("state=%s", bob.Session.State)
	}
}
