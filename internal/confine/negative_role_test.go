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

func TestNegativeRoleSemanticAuthOK(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role: authority.RoleAuth,
		Confer: []authority.Capability{
			authority.CapIdentityHandle, authority.CapSessionKeyDerive, authority.CapAuthorizationPolicy,
		},
		SlotKinds: []string{"ipc_endpoint"},
	})
	for _, f := range fs {
		if f.ID == "NEG-AUTH-ACCEPT" && f.Status != confine.StatusDeniedExpected {
			t.Fatalf("%+v", f)
		}
	}
}

func TestNegativeRoleSemanticAuthBadCap(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role: authority.RoleAuth,
		Confer: []authority.Capability{
			authority.CapIdentityHandle, authority.CapNetworkAcceptLoop,
		},
	})
	for _, f := range fs {
		if f.ID == "NEG-AUTH-ACCEPT" && f.Status != confine.StatusUnexpectedAllow {
			t.Fatalf("%+v", f)
		}
	}
}

func TestNegativeRoleSemanticPlanAuditJournal(t *testing.T) {
	cases := []struct {
		id   string
		in   confine.RoleProbeInput
		want confine.Status
	}{
		{
			id: "NEG-PLAN-WRITE",
			in: confine.RoleProbeInput{
				Role:   authority.RolePlan,
				Confer: []authority.Capability{authority.CapCanonicalManifests, authority.CapPlanOutput},
			},
			want: confine.StatusDeniedExpected,
		},
		{
			id: "NEG-PLAN-WRITE",
			in: confine.RoleProbeInput{
				Role:      authority.RolePlan,
				Confer:    []authority.Capability{authority.CapPlanOutput},
				SlotKinds: []string{"archive_root"},
			},
			want: confine.StatusUnexpectedAllow,
		},
		{
			id: "NEG-AUDIT-DECIDE",
			in: confine.RoleProbeInput{
				Role:   authority.RoleAudit,
				Confer: []authority.Capability{authority.CapReadonlyJournal, authority.CapRedactedEventSink},
			},
			want: confine.StatusDeniedExpected,
		},
		{
			id: "NEG-AUDIT-DECIDE",
			in: confine.RoleProbeInput{
				Role:   authority.RoleAudit,
				Confer: []authority.Capability{authority.CapReadonlyJournal, authority.CapOperationDecisions},
			},
			want: confine.StatusUnexpectedAllow,
		},
		{
			id: "NEG-JOURNAL-NET",
			in: confine.RoleProbeInput{
				Role:   authority.RoleJournal,
				Confer: []authority.Capability{authority.CapJournalDescriptor, authority.CapAuthenticatedRecords},
			},
			want: confine.StatusDeniedExpected,
		},
		{
			id: "NEG-JOURNAL-NET",
			in: confine.RoleProbeInput{
				Role:   authority.RoleJournal,
				Confer: []authority.Capability{authority.CapJournalDescriptor, authority.CapNetwork},
			},
			want: confine.StatusUnexpectedAllow,
		},
	}
	for _, tc := range cases {
		fs := confine.NegativeRoleSemantic(tc.in)
		var got confine.Finding
		for _, f := range fs {
			if f.ID == tc.id {
				got = f
				break
			}
		}
		if got.Status != tc.want {
			t.Fatalf("%s role=%s: got %+v want %s", tc.id, tc.in.Role, got, tc.want)
		}
	}
}
