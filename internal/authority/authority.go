// Package authority holds the normative process authority inventory for
// INT-IC1-0001 / docs/security-architecture.md / IP-A-0001.
//
// This is the machine-checkable manifest used by design and (later) platform
// negative probes. It does not spawn processes.
package authority

import (
	"fmt"
	"sort"
)

// ProcessRole is a privilege-separated Integris runtime role.
type ProcessRole string

const (
	RoleSupervisor ProcessRole = "integrisd-supervisor"
	RoleNet        ProcessRole = "integrisd-net"
	RoleAuth       ProcessRole = "integrisd-auth"
	RoleParser     ProcessRole = "integrisd-parser"
	RoleIndex      ProcessRole = "integrisd-index"
	RolePlan       ProcessRole = "integrisd-plan"
	RoleApply      ProcessRole = "integrisd-apply"
	RoleJournal    ProcessRole = "integrisd-journal"
	RoleAudit      ProcessRole = "integrisd-audit"
)

// Capability is a conferred authority atom.
type Capability string

const (
	CapChildLifecycle       Capability = "child_lifecycle"
	CapPreopenedIPC         Capability = "preopened_ipc"
	CapPolicyIdentity       Capability = "policy_identity"
	CapNetworkSockets       Capability = "network_sockets"
	CapEncryptedFrames      Capability = "encrypted_frames"
	CapIdentityHandle       Capability = "identity_handle"
	CapSessionKeyDerive     Capability = "session_key_derive"
	CapAuthorizationPolicy  Capability = "authorization_policy"
	CapBoundedMessageIPC    Capability = "bounded_message_ipc"
	CapReadonlyArchiveRoot  Capability = "readonly_archive_root"
	CapBoundedIndexOutput   Capability = "bounded_index_output"
	CapCanonicalManifests   Capability = "canonical_manifests"
	CapPlanOutput           Capability = "plan_output"
	CapArchiveRoots         Capability = "archive_staging_quarantine_roots"
	CapJournalDescriptor    Capability = "journal_descriptor"
	CapAuthenticatedRecords Capability = "authenticated_record_input"
	CapReadonlyJournal      Capability = "readonly_journal"
	CapRedactedEventSink    Capability = "redacted_event_sink"

	// Denied atoms referenced by the architecture table.
	CapRemoteContentParser Capability = "remote_content_parser"
	CapArchiveTraversal    Capability = "archive_traversal"
	CapLongTermKeys        Capability = "long_term_keys"
	CapArchiveDescriptors  Capability = "archive_descriptors"
	CapPermanentKeys       Capability = "permanent_keys"
	CapJournalWrites       Capability = "journal_writes"
	CapNetworkAcceptLoop   Capability = "network_accept_loop"
	CapArchiveContents     Capability = "archive_contents"
	CapPublicationRights   Capability = "publication_rights"
	CapNetwork             Capability = "network"
	CapPublication         Capability = "publication"
	CapDeletion            Capability = "deletion"
	CapFilesystemWrites    Capability = "filesystem_writes"
	CapKeys                Capability = "keys"
	CapIdentityKeys        Capability = "identity_keys"
	CapArbitraryPathLookup Capability = "arbitrary_path_lookup"
	CapPolicyDecisions     Capability = "policy_decisions"
	CapArchiveMutation     Capability = "archive_mutation"
	CapOperationDecisions  Capability = "operation_decisions"
	CapArchives            Capability = "archives"
	CapSecrets             Capability = "secrets"
)

// Entry is one process row in the authority map.
type Entry struct {
	Role    ProcessRole
	MayHold []Capability
	MustNot []Capability
}

// Error is a typed inventory failure.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

func reject(code, msg string) error { return &Error{Code: code, Message: msg} }

// Inventory returns the normative M0/M2 process authority map.
func Inventory() []Entry {
	return []Entry{
		{
			Role:    RoleSupervisor,
			MayHold: []Capability{CapChildLifecycle, CapPreopenedIPC, CapPolicyIdentity},
			MustNot: []Capability{CapRemoteContentParser, CapArchiveTraversal, CapLongTermKeys},
		},
		{
			Role:    RoleNet,
			MayHold: []Capability{CapNetworkSockets, CapEncryptedFrames},
			MustNot: []Capability{CapArchiveDescriptors, CapPermanentKeys, CapJournalWrites},
		},
		{
			Role:    RoleAuth,
			MayHold: []Capability{CapIdentityHandle, CapSessionKeyDerive, CapAuthorizationPolicy},
			MustNot: []Capability{CapNetworkAcceptLoop, CapArchiveContents, CapPublicationRights},
		},
		{
			Role:    RoleParser,
			MayHold: []Capability{CapBoundedMessageIPC},
			MustNot: []Capability{CapPermanentKeys, CapArchives, CapNetworkSockets},
		},
		{
			Role:    RoleIndex,
			MayHold: []Capability{CapReadonlyArchiveRoot, CapBoundedIndexOutput},
			MustNot: []Capability{CapNetwork, CapPublication, CapDeletion},
		},
		{
			Role:    RolePlan,
			MayHold: []Capability{CapCanonicalManifests, CapPlanOutput},
			MustNot: []Capability{CapFilesystemWrites, CapNetwork, CapKeys},
		},
		{
			Role:    RoleApply,
			MayHold: []Capability{CapArchiveRoots},
			MustNot: []Capability{CapNetwork, CapIdentityKeys, CapArbitraryPathLookup},
		},
		{
			Role:    RoleJournal,
			MayHold: []Capability{CapJournalDescriptor, CapAuthenticatedRecords},
			MustNot: []Capability{CapPolicyDecisions, CapNetwork, CapArchiveMutation},
		},
		{
			Role:    RoleAudit,
			MayHold: []Capability{CapReadonlyJournal, CapRedactedEventSink},
			MustNot: []Capability{CapOperationDecisions, CapArchives, CapSecrets},
		},
	}
}

// ValidateInventory checks completeness, uniqueness, and may∩mustNot emptiness.
func ValidateInventory(entries []Entry) error {
	if len(entries) == 0 {
		return reject("empty", "inventory is empty")
	}
	seen := map[ProcessRole]struct{}{}
	for _, e := range entries {
		if e.Role == "" {
			return reject("role", "empty role")
		}
		if _, ok := seen[e.Role]; ok {
			return reject("duplicate", "duplicate role "+string(e.Role))
		}
		seen[e.Role] = struct{}{}
		if len(e.MayHold) == 0 {
			return reject("may", string(e.Role)+": MayHold empty")
		}
		if len(e.MustNot) == 0 {
			return reject("must_not", string(e.Role)+": MustNot empty")
		}
		may := map[Capability]struct{}{}
		for _, c := range e.MayHold {
			if c == "" {
				return reject("cap", string(e.Role)+": empty MayHold capability")
			}
			if _, ok := may[c]; ok {
				return reject("duplicate", string(e.Role)+": duplicate MayHold "+string(c))
			}
			may[c] = struct{}{}
		}
		deny := map[Capability]struct{}{}
		for _, c := range e.MustNot {
			if c == "" {
				return reject("cap", string(e.Role)+": empty MustNot capability")
			}
			if _, ok := deny[c]; ok {
				return reject("duplicate", string(e.Role)+": duplicate MustNot "+string(c))
			}
			deny[c] = struct{}{}
			if _, ok := may[c]; ok {
				return reject("overlap", fmt.Sprintf("%s: %s both allowed and denied", e.Role, c))
			}
		}
	}
	required := []ProcessRole{
		RoleSupervisor, RoleNet, RoleAuth, RoleParser, RoleIndex,
		RolePlan, RoleApply, RoleJournal, RoleAudit,
	}
	for _, r := range required {
		if _, ok := seen[r]; !ok {
			return reject("missing", "missing role "+string(r))
		}
	}
	return nil
}

// Allows reports whether role may hold cap according to the inventory.
func Allows(role ProcessRole, cap Capability) (bool, error) {
	for _, e := range Inventory() {
		if e.Role != role {
			continue
		}
		for _, c := range e.MustNot {
			if c == cap {
				return false, nil
			}
		}
		for _, c := range e.MayHold {
			if c == cap {
				return true, nil
			}
		}
		// Not listed as may-hold: default deny (inheritance closed).
		return false, nil
	}
	return false, reject("role", "unknown role "+string(role))
}

// DeniedProbe fails if a MustNot capability would be conferred.
func DeniedProbe(role ProcessRole, conferred []Capability) error {
	for _, c := range conferred {
		ok, err := Allows(role, c)
		if err != nil {
			return err
		}
		if !ok {
			// Check if explicitly must-not for clearer error.
			for _, e := range Inventory() {
				if e.Role != role {
					continue
				}
				for _, d := range e.MustNot {
					if d == c {
						return reject("denied", fmt.Sprintf("%s must not hold %s", role, c))
					}
				}
			}
			return reject("denied", fmt.Sprintf("%s not authorized for %s", role, c))
		}
	}
	return nil
}

// RolesSorted returns inventory roles in stable lexicographic order.
func RolesSorted() []ProcessRole {
	inv := Inventory()
	out := make([]ProcessRole, len(inv))
	for i, e := range inv {
		out[i] = e.Role
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
