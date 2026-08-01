package session_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestAuthenticateProof(t *testing.T) {
	root := bytes.Repeat([]byte{0x55}, 32)
	var sid [16]byte
	sid[0] = 2
	authKey, err := crypto.PeerAuthKey(root, sid)
	if err != nil {
		t.Fatal(err)
	}
	tr := crypto.NewTranscript()
	s := session.NewWithSuites([]session.Version{2, 3}, []string{crypto.SuiteIDAEAD})
	s.Transcript = tr
	if err := s.Negotiate(); err != nil {
		t.Fatal(err)
	}
	proof, err := s.MakeAuthProof(authKey, sid, "i2r")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthenticateProof(authKey, sid, "i2r", proof); err != nil {
		t.Fatal(err)
	}
	if s.State != session.StatePeerAuthenticated {
		t.Fatalf("%s", s.State)
	}

	s2 := session.NewWithSuites([]session.Version{2, 3}, []string{crypto.SuiteIDAEAD})
	s2.Transcript = crypto.NewTranscript()
	_ = s2.Negotiate()
	bad := append([]byte{}, proof...)
	bad[0] ^= 0xff
	if err := s2.AuthenticateProof(authKey, sid, "i2r", bad); err == nil {
		t.Fatal("expected failure")
	}
	if s2.State != session.StateFailed {
		t.Fatalf("%s", s2.State)
	}
}
