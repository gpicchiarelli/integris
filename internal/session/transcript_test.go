package session_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestTranscriptBindingStable(t *testing.T) {
	run := func() (d [32]byte) {
		tr := crypto.NewTranscript()
		s := session.New([]session.Version{2, 3})
		s.Transcript = tr
		if err := s.Negotiate(); err != nil {
			t.Fatal(err)
		}
		if err := s.Authenticate(); err != nil {
			t.Fatal(err)
		}
		if err := s.AuthorizeArchive(); err != nil {
			t.Fatal(err)
		}
		if err := s.Activate(); err != nil {
			t.Fatal(err)
		}
		return tr.Digest()
	}
	a := run()
	b := run()
	if a != b {
		t.Fatalf("digest unstable: %x vs %x", a, b)
	}
	// Different offer order still selects 3, but offered encoding differs.
	tr := crypto.NewTranscript()
	s := session.New([]session.Version{3, 2})
	s.Transcript = tr
	_ = s.Negotiate()
	_ = s.Authenticate()
	_ = s.AuthorizeArchive()
	_ = s.Activate()
	if tr.Digest() == a {
		t.Fatal("offer order should affect transcript")
	}
}
