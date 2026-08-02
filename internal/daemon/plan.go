package daemon

import (
	"github.com/gpicchiarelli/integris/internal/authority"
	"github.com/gpicchiarelli/integris/internal/supervisor"
)

// NetApplyPlan returns a mutual net↔apply grant plan for M2a/M2b (no auth role).
func NetApplyPlan() (supervisor.Plan, error) {
	return supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:   authority.RoleNet,
			Confer: []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{
				authority.RoleApply,
			},
		},
		{
			Role:   authority.RoleApply,
			Confer: []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
			},
		},
	})
}

// AuthNetApplyPlan returns net↔auth + net↔apply for M2c (no parser).
func AuthNetApplyPlan() (supervisor.Plan, error) {
	return supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:   authority.RoleNet,
			Confer: []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{
				authority.RoleAuth,
				authority.RoleApply,
			},
		},
		{
			Role: authority.RoleAuth,
			Confer: []authority.Capability{
				authority.CapIdentityHandle,
				authority.CapSessionKeyDerive,
				authority.CapAuthorizationPolicy,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
			},
		},
		{
			Role:   authority.RoleApply,
			Confer: []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
			},
		},
	})
}

// AuthParserNetApplyPlan returns M2d: auth handshake, parser on data plane, apply.
//
//	net ↔ auth (handshake)
//	net ↔ parser (validated app messages)
//	parser ↔ apply (staging)
func AuthParserNetApplyPlan() (supervisor.Plan, error) {
	return supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:   authority.RoleNet,
			Confer: []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{
				authority.RoleAuth,
				authority.RoleParser,
			},
		},
		{
			Role: authority.RoleAuth,
			Confer: []authority.Capability{
				authority.CapIdentityHandle,
				authority.CapSessionKeyDerive,
				authority.CapAuthorizationPolicy,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
			},
		},
		{
			Role:   authority.RoleParser,
			Confer: []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
				authority.RoleApply,
			},
		},
		{
			Role:   authority.RoleApply,
			Confer: []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{
				authority.RoleParser,
			},
		},
	})
}

// AuthParserNetApplyAuditPlan returns M2e: M2d plus apply→audit redacted sink.
//
//	net ↔ auth (handshake)
//	net ↔ parser (validated app messages)
//	parser ↔ apply (staging)
//	apply ↔ audit (redacted events)
func AuthParserNetApplyAuditPlan() (supervisor.Plan, error) {
	return supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:   authority.RoleNet,
			Confer: []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{
				authority.RoleAuth,
				authority.RoleParser,
			},
		},
		{
			Role: authority.RoleAuth,
			Confer: []authority.Capability{
				authority.CapIdentityHandle,
				authority.CapSessionKeyDerive,
				authority.CapAuthorizationPolicy,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
			},
		},
		{
			Role:   authority.RoleParser,
			Confer: []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
				authority.RoleApply,
			},
		},
		{
			Role:   authority.RoleApply,
			Confer: []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{
				authority.RoleParser,
				authority.RoleAudit,
			},
		},
		{
			Role: authority.RoleAudit,
			Confer: []authority.Capability{
				authority.CapReadonlyJournal,
				authority.CapRedactedEventSink,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleApply,
			},
		},
	})
}

// AuthParserNetApplyJournalPlan returns M2f without audit: journal owns local.jrn.
//
//	parser ↔ apply
//	apply ↔ journal
func AuthParserNetApplyJournalPlan() (supervisor.Plan, error) {
	return supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:   authority.RoleNet,
			Confer: []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{
				authority.RoleAuth,
				authority.RoleParser,
			},
		},
		{
			Role: authority.RoleAuth,
			Confer: []authority.Capability{
				authority.CapIdentityHandle,
				authority.CapSessionKeyDerive,
				authority.CapAuthorizationPolicy,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
			},
		},
		{
			Role:   authority.RoleParser,
			Confer: []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
				authority.RoleApply,
			},
		},
		{
			Role:   authority.RoleApply,
			Confer: []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{
				authority.RoleParser,
				authority.RoleJournal,
			},
		},
		{
			Role: authority.RoleJournal,
			Confer: []authority.Capability{
				authority.CapJournalDescriptor,
				authority.CapAuthenticatedRecords,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleApply,
			},
		},
	})
}

// AuthParserNetApplyJournalAuditPlan returns M2f: journal owns local.jrn; audit
// is journal's extra peer (apply has only one ExtraPeer slot).
//
//	parser ↔ apply
//	apply ↔ journal (durable appends + audit relay)
//	journal ↔ audit (redacted events)
func AuthParserNetApplyJournalAuditPlan() (supervisor.Plan, error) {
	return supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:   authority.RoleNet,
			Confer: []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{
				authority.RoleAuth,
				authority.RoleParser,
			},
		},
		{
			Role: authority.RoleAuth,
			Confer: []authority.Capability{
				authority.CapIdentityHandle,
				authority.CapSessionKeyDerive,
				authority.CapAuthorizationPolicy,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
			},
		},
		{
			Role:   authority.RoleParser,
			Confer: []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
				authority.RoleApply,
			},
		},
		{
			Role:   authority.RoleApply,
			Confer: []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{
				authority.RoleParser,
				authority.RoleJournal,
			},
		},
		{
			Role: authority.RoleJournal,
			Confer: []authority.Capability{
				authority.CapJournalDescriptor,
				authority.CapAuthenticatedRecords,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleApply,
				authority.RoleAudit,
			},
		},
		{
			Role: authority.RoleAudit,
			Confer: []authority.Capability{
				authority.CapReadonlyJournal,
				authority.CapRedactedEventSink,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleJournal,
			},
		},
	})
}

// AuthParserNetPlanIndexApplyJournalAuditPlan returns M2h: index between plan and apply.
//
//	parser ↔ plan
//	plan ↔ index (readonly dest Scan at commit)
//	index ↔ apply
//	apply ↔ journal
//	journal ↔ audit
func AuthParserNetPlanIndexApplyJournalAuditPlan() (supervisor.Plan, error) {
	return m2hReceivePlan(false)
}

// AuthParserNetPlanIndexApplyJournalAuditPeerPlan returns M2h plus auth↔audit
// for M2j peer admit/deny events (used when ServeOptions.Peers is set).
func AuthParserNetPlanIndexApplyJournalAuditPeerPlan() (supervisor.Plan, error) {
	return m2hReceivePlan(true)
}

func m2hReceivePlan(authAudit bool) (supervisor.Plan, error) {
	authPeers := []authority.ProcessRole{authority.RoleNet}
	auditPeers := []authority.ProcessRole{authority.RoleJournal}
	if authAudit {
		authPeers = append(authPeers, authority.RoleAudit)
		auditPeers = append(auditPeers, authority.RoleAuth)
	}
	return supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:   authority.RoleNet,
			Confer: []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{
				authority.RoleAuth,
				authority.RoleParser,
			},
		},
		{
			Role: authority.RoleAuth,
			Confer: []authority.Capability{
				authority.CapIdentityHandle,
				authority.CapSessionKeyDerive,
				authority.CapAuthorizationPolicy,
			},
			IPCPeers: authPeers,
		},
		{
			Role:   authority.RoleParser,
			Confer: []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
				authority.RolePlan,
			},
		},
		{
			Role: authority.RolePlan,
			Confer: []authority.Capability{
				authority.CapCanonicalManifests,
				authority.CapPlanOutput,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleParser,
				authority.RoleIndex,
			},
		},
		{
			Role: authority.RoleIndex,
			Confer: []authority.Capability{
				authority.CapReadonlyArchiveRoot,
				authority.CapBoundedIndexOutput,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RolePlan,
				authority.RoleApply,
			},
		},
		{
			Role:   authority.RoleApply,
			Confer: []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{
				authority.RoleIndex,
				authority.RoleJournal,
			},
		},
		{
			Role: authority.RoleJournal,
			Confer: []authority.Capability{
				authority.CapJournalDescriptor,
				authority.CapAuthenticatedRecords,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleApply,
				authority.RoleAudit,
			},
		},
		{
			Role: authority.RoleAudit,
			Confer: []authority.Capability{
				authority.CapReadonlyJournal,
				authority.CapRedactedEventSink,
			},
			IPCPeers: auditPeers,
		},
	})
}

// AuthParserNetPlanApplyJournalAuditPlan returns M2g: plan between parser and apply.
//
//	parser ↔ plan (canonical manifest authorize)
//	plan ↔ apply (staging)
//	apply ↔ journal
//	journal ↔ audit
func AuthParserNetPlanApplyJournalAuditPlan() (supervisor.Plan, error) {
	return supervisor.BuildPlan([]supervisor.ChildSpec{
		{
			Role:   authority.RoleNet,
			Confer: []authority.Capability{authority.CapNetworkSockets, authority.CapEncryptedFrames},
			IPCPeers: []authority.ProcessRole{
				authority.RoleAuth,
				authority.RoleParser,
			},
		},
		{
			Role: authority.RoleAuth,
			Confer: []authority.Capability{
				authority.CapIdentityHandle,
				authority.CapSessionKeyDerive,
				authority.CapAuthorizationPolicy,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
			},
		},
		{
			Role:   authority.RoleParser,
			Confer: []authority.Capability{authority.CapBoundedMessageIPC},
			IPCPeers: []authority.ProcessRole{
				authority.RoleNet,
				authority.RolePlan,
			},
		},
		{
			Role: authority.RolePlan,
			Confer: []authority.Capability{
				authority.CapCanonicalManifests,
				authority.CapPlanOutput,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleParser,
				authority.RoleApply,
			},
		},
		{
			Role:   authority.RoleApply,
			Confer: []authority.Capability{authority.CapArchiveRoots},
			IPCPeers: []authority.ProcessRole{
				authority.RolePlan,
				authority.RoleJournal,
			},
		},
		{
			Role: authority.RoleJournal,
			Confer: []authority.Capability{
				authority.CapJournalDescriptor,
				authority.CapAuthenticatedRecords,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleApply,
				authority.RoleAudit,
			},
		},
		{
			Role: authority.RoleAudit,
			Confer: []authority.Capability{
				authority.CapReadonlyJournal,
				authority.CapRedactedEventSink,
			},
			IPCPeers: []authority.ProcessRole{
				authority.RoleJournal,
			},
		},
	})
}
