package authority_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
)

func TestInventoryValid(t *testing.T) {
	if err := authority.ValidateInventory(authority.Inventory()); err != nil {
		t.Fatal(err)
	}
}

func TestNineRoles(t *testing.T) {
	if got := len(authority.RolesSorted()); got != 9 {
		t.Fatalf("roles=%d", got)
	}
}

func TestParserCannotHoldKeys(t *testing.T) {
	ok, err := authority.Allows(authority.RoleParser, authority.CapPermanentKeys)
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	err = authority.DeniedProbe(authority.RoleParser, []authority.Capability{
		authority.CapPermanentKeys,
	})
	var e *authority.Error
	if err == nil || !asAuth(err, &e) || e.Code != "denied" {
		t.Fatalf("got %v", err)
	}
}

func TestApplyMayHoldRoots(t *testing.T) {
	ok, err := authority.Allows(authority.RoleApply, authority.CapArchiveRoots)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestNetMustNotJournalWrites(t *testing.T) {
	ok, err := authority.Allows(authority.RoleNet, authority.CapJournalWrites)
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestDefaultDenyUnlisted(t *testing.T) {
	ok, err := authority.Allows(authority.RolePlan, authority.CapNetworkSockets)
	if err != nil || ok {
		t.Fatalf("unlisted must deny: ok=%v err=%v", ok, err)
	}
}

func asAuth(err error, target **authority.Error) bool {
	if e, ok := err.(*authority.Error); ok {
		*target = e
		return true
	}
	return false
}
