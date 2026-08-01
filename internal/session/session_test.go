package session_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/session"
)

func TestHappyPath(t *testing.T) {
	s := session.New([]session.Version{1, 2, 3})
	if err := s.Negotiate(); err != nil {
		t.Fatal(err)
	}
	if s.Selected != 3 {
		t.Fatalf("selected=%d", s.Selected)
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
	if err := s.AcceptNext(); err != nil {
		t.Fatal(err)
	}
	if err := s.Invariants(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.State != session.StateClosed {
		t.Fatalf("%s", s.State)
	}
}

func TestNoCommonVersionFails(t *testing.T) {
	s := session.New([]session.Version{1})
	err := s.Negotiate()
	var e *session.Error
	if err == nil || !asS(err, &e) || s.State != session.StateFailed {
		t.Fatalf("got %v state=%s", err, s.State)
	}
}

func TestMutationRequiresAuth(t *testing.T) {
	s := session.Session{State: session.StateActive, ProductMutation: true}
	if err := s.Invariants(); err == nil {
		t.Fatal("expected MutationIsAuthorized failure")
	}
}

func TestRejectReplay(t *testing.T) {
	s := session.New([]session.Version{2, 3})
	_ = s.Negotiate()
	_ = s.Authenticate()
	_ = s.AuthorizeArchive()
	_ = s.Activate()
	if err := s.RejectReplay(); err != nil {
		t.Fatal(err)
	}
	if s.ReplayAccepted || s.State != session.StateFailed {
		t.Fatalf("%+v", s)
	}
	if err := s.Invariants(); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptNextCap(t *testing.T) {
	s := session.New([]session.Version{3})
	_ = s.Negotiate()
	_ = s.Authenticate()
	_ = s.AuthorizeArchive()
	_ = s.Activate()
	for i := 0; i < session.MaxMessages; i++ {
		if err := s.AcceptNext(); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AcceptNext(); err == nil {
		t.Fatal("expected limit")
	}
}

func asS(err error, target **session.Error) bool {
	if e, ok := err.(*session.Error); ok {
		*target = e
		return true
	}
	return false
}
