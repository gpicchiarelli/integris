package session_test

import (
	"bytes"
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/session"
)

func peerAuthenticatedSession(t *testing.T) (session.Session, []byte, [16]byte) {
	t.Helper()
	root := bytes.Repeat([]byte{0x55}, 32)
	var sid [16]byte
	sid[0] = 2
	peerKey, err := crypto.PeerAuthKey(root, sid)
	if err != nil {
		t.Fatal(err)
	}
	archKey, err := crypto.ArchiveAuthKey(root, sid)
	if err != nil {
		t.Fatal(err)
	}
	s := session.NewWithSuites([]session.Version{2, 3}, []string{crypto.SuiteIDAEAD})
	s.Transcript = crypto.NewTranscript()
	if err := s.Negotiate(); err != nil {
		t.Fatal(err)
	}
	p1, _ := s.MakeAuthProof(peerKey, sid, "i2r")
	p2, _ := s.MakeAuthProof(peerKey, sid, "r2i")
	if err := s.AuthenticateProof(peerKey, sid, "i2r", p1); err != nil {
		t.Fatal(err)
	}
	if err := s.AuthenticateProof(peerKey, sid, "r2i", p2); err != nil {
		t.Fatal(err)
	}
	return s, archKey, sid
}

func TestAuthorizeArchiveProof(t *testing.T) {
	s, archKey, sid := peerAuthenticatedSession(t)
	proof, err := s.MakeArchiveProof(archKey, sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AuthorizeArchiveProof(archKey, sid, proof); err != nil {
		t.Fatal(err)
	}
	if s.State != session.StateArchiveAuthorized || !s.ArchiveAuthorized {
		t.Fatalf("%s auth=%v", s.State, s.ArchiveAuthorized)
	}

	s2, archKey2, sid2 := peerAuthenticatedSession(t)
	ok, _ := s2.MakeArchiveProof(archKey2, sid2)
	bad := append([]byte{}, ok...)
	bad[0] ^= 0xff
	if err := s2.AuthorizeArchiveProof(archKey2, sid2, bad); err == nil {
		t.Fatal("expected failure")
	}
	if s2.State != session.StateFailed {
		t.Fatalf("%s", s2.State)
	}
}
