package session_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/crypto"
	"github.com/gpicchiarelli/integris/internal/session"
)

func TestSelectSuite(t *testing.T) {
	s, ok := session.SelectSuite(session.LocalSuites, []string{"other", crypto.SuiteIDAEAD})
	if !ok || s != crypto.SuiteIDAEAD {
		t.Fatalf("%q %v", s, ok)
	}
	if _, ok := session.SelectSuite(session.LocalSuites, []string{"nope"}); ok {
		t.Fatal("expected reject")
	}
}

func TestNegotiateRequiresSuite(t *testing.T) {
	s := session.NewWithSuites([]session.Version{2, 3}, []string{"unknown-suite"})
	if err := s.Negotiate(); err == nil {
		t.Fatal("expected suite failure")
	}
	if s.State != session.StateFailed {
		t.Fatalf("state=%s", s.State)
	}
}

func TestNegotiateSelectsSuite(t *testing.T) {
	tr := crypto.NewTranscript()
	s := session.NewWithSuites([]session.Version{2, 3}, []string{crypto.SuiteIDAEAD})
	s.Transcript = tr
	if err := s.Negotiate(); err != nil {
		t.Fatal(err)
	}
	if s.SelectedSuite != crypto.SuiteIDAEAD {
		t.Fatalf("%q", s.SelectedSuite)
	}
}

func TestConfirmAccept(t *testing.T) {
	s := session.NewWithSuites([]session.Version{2, 3}, []string{crypto.SuiteIDAEAD})
	if err := s.Negotiate(); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmAccept(s.Selected, s.SelectedSuite); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmAccept(s.Selected, "wrong"); err == nil {
		t.Fatal("expected suite mismatch")
	}
	if s.State != session.StateFailed {
		t.Fatalf("state=%s", s.State)
	}
}
