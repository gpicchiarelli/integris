package confine_test

import (
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/confine"
)

func TestNegativeRoleSemanticNetOK(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role:      authority.RoleNet,
		Confer:    []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
		SlotKinds: []string{"ipc_endpoint"},
	})
	want := map[string]confine.Status{
		"NEG-NET-ARCHIVE": confine.StatusDeniedExpected,
		"NEG-NET-KEYS":    confine.StatusDeniedExpected,
		"NEG-NET-JOURNAL": confine.StatusDeniedExpected,
	}
	for _, f := range fs {
		if st, ok := want[f.ID]; ok && f.Status != st {
			t.Fatalf("%s: %+v", f.ID, f)
		}
	}
}

func TestNegativeRoleSemanticNetBadCap(t *testing.T) {
	cases := []struct {
		id     string
		confer []authority.Capability
		slots  []string
	}{
		{
			id: "NEG-NET-ARCHIVE",
			confer: []authority.Capability{
				authority.CapNetworkSockets,
			},
			slots: []string{"archive_root"},
		},
		{
			id: "NEG-NET-KEYS",
			confer: []authority.Capability{
				authority.CapNetworkSockets, authority.CapPermanentKeys,
			},
		},
		{
			id: "NEG-NET-JOURNAL",
			confer: []authority.Capability{
				authority.CapNetworkSockets, authority.CapJournalWrites,
			},
		},
	}
	for _, tc := range cases {
		fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
			Role:      authority.RoleNet,
			Confer:    tc.confer,
			SlotKinds: tc.slots,
		})
		for _, f := range fs {
			if f.ID == tc.id && f.Status != confine.StatusUnexpectedAllow {
				t.Fatalf("%s: %+v", tc.id, f)
			}
		}
	}
}

func TestNegativeRoleSemanticParserOK(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role:      authority.RoleParser,
		Confer:    []authority.Capability{authority.CapBoundedMessageIPC},
		SlotKinds: []string{"ipc_endpoint"},
	})
	want := map[string]confine.Status{
		"NEG-PARSER-NET":      confine.StatusDeniedExpected,
		"NEG-PARSER-KEYS":     confine.StatusDeniedExpected,
		"NEG-PARSER-ARCHIVES": confine.StatusDeniedExpected,
	}
	for _, f := range fs {
		if st, ok := want[f.ID]; ok && f.Status != st {
			t.Fatalf("%s: %+v", f.ID, f)
		}
	}
}

func TestNegativeRoleSemanticParserBadCap(t *testing.T) {
	cases := []struct {
		id     string
		confer []authority.Capability
		slots  []string
	}{
		{
			id: "NEG-PARSER-NET",
			confer: []authority.Capability{
				authority.CapBoundedMessageIPC, authority.CapNetworkSockets,
			},
		},
		{
			id: "NEG-PARSER-KEYS",
			confer: []authority.Capability{
				authority.CapBoundedMessageIPC, authority.CapPermanentKeys,
			},
		},
		{
			id: "NEG-PARSER-ARCHIVES",
			confer: []authority.Capability{
				authority.CapBoundedMessageIPC, authority.CapArchives,
			},
		},
		{
			id: "NEG-PARSER-ARCHIVES",
			confer: []authority.Capability{
				authority.CapBoundedMessageIPC,
			},
			slots: []string{"archive_root"},
		},
	}
	for _, tc := range cases {
		fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
			Role:      authority.RoleParser,
			Confer:    tc.confer,
			SlotKinds: tc.slots,
		})
		for _, f := range fs {
			if f.ID == tc.id && f.Status != confine.StatusUnexpectedAllow {
				t.Fatalf("%s: %+v", tc.id, f)
			}
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
	want := map[string]confine.Status{
		"NEG-AUTH-ACCEPT":   confine.StatusDeniedExpected,
		"NEG-AUTH-CONTENTS": confine.StatusDeniedExpected,
		"NEG-AUTH-PUB":      confine.StatusDeniedExpected,
	}
	for _, f := range fs {
		if st, ok := want[f.ID]; ok && f.Status != st {
			t.Fatalf("%s: %+v", f.ID, f)
		}
	}
}

func TestNegativeRoleSemanticAuthBadCap(t *testing.T) {
	cases := []struct {
		id     string
		confer []authority.Capability
	}{
		{
			id: "NEG-AUTH-ACCEPT",
			confer: []authority.Capability{
				authority.CapIdentityHandle, authority.CapNetworkAcceptLoop,
			},
		},
		{
			id: "NEG-AUTH-CONTENTS",
			confer: []authority.Capability{
				authority.CapIdentityHandle, authority.CapArchiveContents,
			},
		},
		{
			id: "NEG-AUTH-PUB",
			confer: []authority.Capability{
				authority.CapIdentityHandle, authority.CapPublicationRights,
			},
		},
	}
	for _, tc := range cases {
		fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
			Role:   authority.RoleAuth,
			Confer: tc.confer,
		})
		for _, f := range fs {
			if f.ID == tc.id && f.Status != confine.StatusUnexpectedAllow {
				t.Fatalf("%s: %+v", tc.id, f)
			}
		}
	}
}

func TestNegativeRoleSemanticAuthBadSlot(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role:      authority.RoleAuth,
		Confer:    []authority.Capability{authority.CapIdentityHandle},
		SlotKinds: []string{"archive_root"},
	})
	for _, f := range fs {
		if f.ID == "NEG-AUTH-CONTENTS" && f.Status != confine.StatusUnexpectedAllow {
			t.Fatalf("%+v", f)
		}
	}
}

func TestNegativeRoleSemanticIndexOK(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role: authority.RoleIndex,
		Confer: []authority.Capability{
			authority.CapReadonlyArchiveRoot, authority.CapBoundedIndexOutput,
		},
		SlotKinds: []string{"archive_root"},
	})
	want := map[string]confine.Status{
		"NEG-INDEX-PUB":    confine.StatusDeniedExpected,
		"NEG-INDEX-DELETE": confine.StatusDeniedExpected,
	}
	for _, f := range fs {
		if st, ok := want[f.ID]; ok && f.Status != st {
			t.Fatalf("%s: %+v", f.ID, f)
		}
	}
}

func TestNegativeRoleSemanticIndexBadCap(t *testing.T) {
	cases := []struct {
		id     string
		confer []authority.Capability
	}{
		{
			id: "NEG-INDEX-PUB",
			confer: []authority.Capability{
				authority.CapReadonlyArchiveRoot, authority.CapPublication,
			},
		},
		{
			id: "NEG-INDEX-DELETE",
			confer: []authority.Capability{
				authority.CapReadonlyArchiveRoot, authority.CapDeletion,
			},
		},
	}
	for _, tc := range cases {
		fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
			Role:   authority.RoleIndex,
			Confer: tc.confer,
		})
		for _, f := range fs {
			if f.ID == tc.id && f.Status != confine.StatusUnexpectedAllow {
				t.Fatalf("%s: %+v", tc.id, f)
			}
		}
	}
}

func TestNegativeRoleSemanticApplyOK(t *testing.T) {
	fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
		Role:      authority.RoleApply,
		Confer:    []authority.Capability{authority.CapArchiveRoots},
		SlotKinds: []string{"archive_root"},
	})
	want := map[string]confine.Status{
		"NEG-APPLY-KEYS": confine.StatusDeniedExpected,
		"NEG-APPLY-PATH": confine.StatusDeniedExpected,
	}
	for _, f := range fs {
		if st, ok := want[f.ID]; ok && f.Status != st {
			t.Fatalf("%s: %+v", f.ID, f)
		}
	}
}

func TestNegativeRoleSemanticApplyBadCap(t *testing.T) {
	cases := []struct {
		id     string
		confer []authority.Capability
	}{
		{
			id: "NEG-APPLY-KEYS",
			confer: []authority.Capability{
				authority.CapArchiveRoots, authority.CapIdentityKeys,
			},
		},
		{
			id: "NEG-APPLY-PATH",
			confer: []authority.Capability{
				authority.CapArchiveRoots, authority.CapArbitraryPathLookup,
			},
		},
	}
	for _, tc := range cases {
		fs := confine.NegativeRoleSemantic(confine.RoleProbeInput{
			Role:   authority.RoleApply,
			Confer: tc.confer,
		})
		for _, f := range fs {
			if f.ID == tc.id && f.Status != confine.StatusUnexpectedAllow {
				t.Fatalf("%s: %+v", tc.id, f)
			}
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
			id: "NEG-AUDIT-ARCHIVES",
			in: confine.RoleProbeInput{
				Role:   authority.RoleAudit,
				Confer: []authority.Capability{authority.CapReadonlyJournal, authority.CapRedactedEventSink},
			},
			want: confine.StatusDeniedExpected,
		},
		{
			id: "NEG-AUDIT-ARCHIVES",
			in: confine.RoleProbeInput{
				Role:   authority.RoleAudit,
				Confer: []authority.Capability{authority.CapReadonlyJournal, authority.CapArchives},
			},
			want: confine.StatusUnexpectedAllow,
		},
		{
			id: "NEG-AUDIT-ARCHIVES",
			in: confine.RoleProbeInput{
				Role:      authority.RoleAudit,
				Confer:    []authority.Capability{authority.CapReadonlyJournal},
				SlotKinds: []string{"archive_root"},
			},
			want: confine.StatusUnexpectedAllow,
		},
		{
			id: "NEG-AUDIT-SECRETS",
			in: confine.RoleProbeInput{
				Role:   authority.RoleAudit,
				Confer: []authority.Capability{authority.CapReadonlyJournal, authority.CapRedactedEventSink},
			},
			want: confine.StatusDeniedExpected,
		},
		{
			id: "NEG-AUDIT-SECRETS",
			in: confine.RoleProbeInput{
				Role:   authority.RoleAudit,
				Confer: []authority.Capability{authority.CapReadonlyJournal, authority.CapSecrets},
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
		{
			id: "NEG-JOURNAL-POLICY",
			in: confine.RoleProbeInput{
				Role:   authority.RoleJournal,
				Confer: []authority.Capability{authority.CapJournalDescriptor, authority.CapAuthenticatedRecords},
			},
			want: confine.StatusDeniedExpected,
		},
		{
			id: "NEG-JOURNAL-POLICY",
			in: confine.RoleProbeInput{
				Role:   authority.RoleJournal,
				Confer: []authority.Capability{authority.CapJournalDescriptor, authority.CapPolicyDecisions},
			},
			want: confine.StatusUnexpectedAllow,
		},
		{
			id: "NEG-JOURNAL-MUTATE",
			in: confine.RoleProbeInput{
				Role:   authority.RoleJournal,
				Confer: []authority.Capability{authority.CapJournalDescriptor, authority.CapAuthenticatedRecords},
			},
			want: confine.StatusDeniedExpected,
		},
		{
			id: "NEG-JOURNAL-MUTATE",
			in: confine.RoleProbeInput{
				Role:   authority.RoleJournal,
				Confer: []authority.Capability{authority.CapJournalDescriptor, authority.CapArchiveMutation},
			},
			want: confine.StatusUnexpectedAllow,
		},
		{
			id: "NEG-JOURNAL-MUTATE",
			in: confine.RoleProbeInput{
				Role:      authority.RoleJournal,
				Confer:    []authority.Capability{authority.CapJournalDescriptor},
				SlotKinds: []string{"archive_root"},
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
