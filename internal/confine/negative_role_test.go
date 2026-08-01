package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestNegativeRoleSemanticNetOK(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role:   authority.RoleNet,
		Confer: []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
		SlotKinds: []string{"ipc_endpoint"},
	})
	var netF confine.Finding
	for _, f := range fs {
		if f.ID == "NEG-NET-ARCHIVE" {
			netF = f
		}
	}
	if netF.Status != confine.StatusDeniedExpected {
		t.Fatalf("%+v", netF)
	}
}

func TestNegativeRoleSemanticNetBadSlot(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role:      authority.RoleNet,
		Confer:    []authority.Capability{authority.CapNetworkSockets},
		SlotKinds: []string{"archive_root"},
	})
	for _, f := range fs {
		if f.ID == "NEG-NET-ARCHIVE" && f.Status != confine.StatusUnexpectedAllow {
			t.Fatalf("%+v", f)
		}
	}
}

func TestNegativeRoleSemanticParserOK(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role:      authority.RoleParser,
		Confer:    []authority.Capability{authority.CapBoundedMessageIPC},
		SlotKinds: []string{"ipc_endpoint"},
	})
	for _, f := range fs {
		if f.ID == "NEG-PARSER-NET" && f.Status != confine.StatusDeniedExpected {
			t.Fatalf("%+v", f)
		}
	}
}

func TestNegativeRoleSemanticParserBadCap(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role:   authority.RoleParser,
		Confer: []authority.Capability{authority.CapBoundedMessageIPC, authority.CapNetworkSockets},
	})
	for _, f := range fs {
		if f.ID == "NEG-PARSER-NET" && f.Status != confine.StatusUnexpectedAllow {
			t.Fatalf("%+v", f)
		}
	}
}
