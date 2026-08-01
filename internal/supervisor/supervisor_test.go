package supervisor_test

import (
	"errors"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

func TestMinimalRuntimePlan(t *testing.T) {
	p, err := supervisor.MinimalRuntimePlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Children) != 9 {
		t.Fatalf("children=%d", len(p.Children))
	}
}

func TestRejectDeniedGrant(t *testing.T) {
	_, err := supervisor.BuildPlan([]supervisor.ChildSpec{{
		Role:   authority.RoleParser,
		Confer: []authority.Capability{authority.CapPermanentKeys},
	}})
	var e *supervisor.Error
	if !errors.As(err, &e) || e.Code != "denied" {
		t.Fatalf("got %v", err)
	}
}

func TestRejectEmptyConfer(t *testing.T) {
	_, err := supervisor.BuildPlan([]supervisor.ChildSpec{{
		Role: authority.RoleNet, Confer: nil,
	}})
	var e *supervisor.Error
	if !errors.As(err, &e) || e.Code != "confer" {
		t.Fatalf("got %v", err)
	}
}
