package session_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/session"
)

func negotiatedAuthSession(t *testing.T) (session.Session, []byte, [16]byte) {
	t.Helper()
	root := bytes.Repeat([]byte{0x55}, 32)
	var sid [16]byte
	sid[0] = 2
	authKey, err := crypto.PeerAuthKey(root, sid)
	if err != nil {
		t.Fatal(err)
	}
	s := session.NewWithSuites([]session.Version{2, 3}, []string{crypto.SuiteIDAEAD})
	s.Transcript = crypto.NewTranscript()
	if err := s.Negotiate(); err != nil {
		t.Fatal(err)
	}
	return s, authKey, sid
}

func TestAuthenticateProofMutual(t *testing.T) {
	s, authKey, sid := negotiatedAuthSession(t)
	p1, err := s.MakeAuthProof(authKey, sid, "i2r")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := s.MakeAuthProof(authKey, sid, "r2i")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthenticateProof(authKey, sid, "i2r", p1); err != nil {
		t.Fatal(err)
	}
	if s.State != session.StateNegotiated || s.PeerAuthenticated {
		t.Fatalf("one-sided should stay NEGOTIATED, got %s auth=%v", s.State, s.PeerAuthenticated)
	}
	if err := s.AuthenticateProof(authKey, sid, "r2i", p2); err != nil {
		t.Fatal(err)
	}
	if s.State != session.StatePeerAuthenticated || !s.AuthI2R || !s.AuthR2I {
		t.Fatalf("%s i2r=%v r2i=%v", s.State, s.AuthI2R, s.AuthR2I)
	}
	if err := s.Invariants(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticateProofOrderIndependent(t *testing.T) {
	s, authKey, sid := negotiatedAuthSession(t)
	p1, _ := s.MakeAuthProof(authKey, sid, "i2r")
	p2, _ := s.MakeAuthProof(authKey, sid, "r2i")
	if err := s.AuthenticateProof(authKey, sid, "r2i", p2); err != nil {
		t.Fatal(err)
	}
	if err := s.AuthenticateProof(authKey, sid, "i2r", p1); err != nil {
		t.Fatal(err)
	}
	if s.State != session.StatePeerAuthenticated {
		t.Fatalf("%s", s.State)
	}
}

func TestAuthenticateProofRejectsBadAndDuplicate(t *testing.T) {
	s, authKey, sid := negotiatedAuthSession(t)
	p1, _ := s.MakeAuthProof(authKey, sid, "i2r")
	bad := append([]byte{}, p1...)
	bad[0] ^= 0xff
	if err := s.AuthenticateProof(authKey, sid, "i2r", bad); err == nil {
		t.Fatal("expected mismatch failure")
	}
	if s.State != session.StateFailed {
		t.Fatalf("%s", s.State)
	}

	s2, authKey2, sid2 := negotiatedAuthSession(t)
	ok, _ := s2.MakeAuthProof(authKey2, sid2, "i2r")
	if err := s2.AuthenticateProof(authKey2, sid2, "i2r", ok); err != nil {
		t.Fatal(err)
	}
	if err := s2.AuthenticateProof(authKey2, sid2, "i2r", ok); err == nil {
		t.Fatal("expected duplicate failure")
	}
	if s2.State != session.StateFailed {
		t.Fatalf("%s", s2.State)
	}
}
