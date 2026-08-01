package confine

import (
	"runtime"
	"strings"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// RoleProbeInput is conferral inventory for role-semantic negative probes.
// SlotKinds are opaque descriptor kind strings (e.g. "archive_root").
type RoleProbeInput struct {
	Role      authority.ProcessRole
	Confer    []authority.Capability
	SlotKinds []string
}

// NegativeRoleSemantic checks that MustNot capabilities and forbidden descriptor
// slots are absent from the conferred inventory (VER-ARCH-001 style). This is
// not an OS syscall denial probe.
func NegativeRoleSemantic(in RoleProbeInput) []Finding {
	plat := runtime.GOOS + "/" + runtime.GOARCH
	return []Finding{
		negNetArchive(plat, in),
		negParserNet(plat, in),
		negAuthAccept(plat, in),
		negAuthContents(plat, in),
		negAuthPub(plat, in),
		negIndexPub(plat, in),
		negIndexDelete(plat, in),
		negApplyKeys(plat, in),
		negApplyPath(plat, in),
		negPlanWrite(plat, in),
		negAuditDecide(plat, in),
		negJournalNet(plat, in),
	}
}

func negNetArchive(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-NET-ARCHIVE", Platform: plat, Control: "archive_descriptors",
	}
	if in.Role != authority.RoleNet {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-net only"
		return base
	}
	if hasCap(in.Confer, authority.CapArchiveDescriptors) ||
		hasCap(in.Confer, authority.CapArchiveRoots) ||
		hasCap(in.Confer, authority.CapReadonlyArchiveRoot) ||
		hasCap(in.Confer, authority.CapArchives) ||
		hasArchiveSlot(in.SlotKinds) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "net role conferred archive capability or slot"
		return base
	}
	ok, err := authority.Allows(authority.RoleNet, authority.CapArchiveDescriptors)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows archive_descriptors for net"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "net lacks archive descriptors in inventory and conferral"
	return base
}

func negParserNet(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-PARSER-NET", Platform: plat, Control: "network_sockets",
	}
	if in.Role != authority.RoleParser {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-parser only"
		return base
	}
	if hasCap(in.Confer, authority.CapNetworkSockets) ||
		hasCap(in.Confer, authority.CapNetwork) ||
		hasCap(in.Confer, authority.CapNetworkAcceptLoop) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "parser role conferred network capability"
		return base
	}
	ok, err := authority.Allows(authority.RoleParser, authority.CapNetworkSockets)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows network_sockets for parser"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "parser lacks network_sockets in inventory and conferral"
	return base
}

func negAuthAccept(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-AUTH-ACCEPT", Platform: plat, Control: "network_accept_loop",
	}
	if in.Role != authority.RoleAuth {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-auth only"
		return base
	}
	if hasCap(in.Confer, authority.CapNetworkAcceptLoop) ||
		hasCap(in.Confer, authority.CapNetworkSockets) ||
		hasCap(in.Confer, authority.CapNetwork) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "auth role conferred network accept or socket capability"
		return base
	}
	ok, err := authority.Allows(authority.RoleAuth, authority.CapNetworkAcceptLoop)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows network_accept_loop for auth"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "auth lacks network_accept_loop in inventory and conferral"
	return base
}

func negAuthContents(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-AUTH-CONTENTS", Platform: plat, Control: "archive_contents",
	}
	if in.Role != authority.RoleAuth {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-auth only"
		return base
	}
	if hasCap(in.Confer, authority.CapArchiveContents) ||
		hasCap(in.Confer, authority.CapArchiveDescriptors) ||
		hasCap(in.Confer, authority.CapArchiveRoots) ||
		hasCap(in.Confer, authority.CapReadonlyArchiveRoot) ||
		hasCap(in.Confer, authority.CapArchives) ||
		hasArchiveSlot(in.SlotKinds) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "auth role conferred archive contents capability or slot"
		return base
	}
	ok, err := authority.Allows(authority.RoleAuth, authority.CapArchiveContents)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows archive_contents for auth"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "auth lacks archive_contents in inventory and conferral"
	return base
}

func negAuthPub(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-AUTH-PUB", Platform: plat, Control: "publication_rights",
	}
	if in.Role != authority.RoleAuth {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-auth only"
		return base
	}
	if hasCap(in.Confer, authority.CapPublicationRights) ||
		hasCap(in.Confer, authority.CapPublication) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "auth role conferred publication capability"
		return base
	}
	ok, err := authority.Allows(authority.RoleAuth, authority.CapPublicationRights)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows publication_rights for auth"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "auth lacks publication_rights in inventory and conferral"
	return base
}

func negIndexPub(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-INDEX-PUB", Platform: plat, Control: "publication",
	}
	if in.Role != authority.RoleIndex {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-index only"
		return base
	}
	if hasCap(in.Confer, authority.CapPublication) ||
		hasCap(in.Confer, authority.CapPublicationRights) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "index role conferred publication capability"
		return base
	}
	ok, err := authority.Allows(authority.RoleIndex, authority.CapPublication)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows publication for index"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "index lacks publication in inventory and conferral"
	return base
}

func negIndexDelete(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-INDEX-DELETE", Platform: plat, Control: "deletion",
	}
	if in.Role != authority.RoleIndex {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-index only"
		return base
	}
	if hasCap(in.Confer, authority.CapDeletion) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "index role conferred deletion capability"
		return base
	}
	ok, err := authority.Allows(authority.RoleIndex, authority.CapDeletion)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows deletion for index"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "index lacks deletion in inventory and conferral"
	return base
}

func negApplyKeys(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-APPLY-KEYS", Platform: plat, Control: "identity_keys",
	}
	if in.Role != authority.RoleApply {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-apply only"
		return base
	}
	if hasCap(in.Confer, authority.CapIdentityKeys) ||
		hasCap(in.Confer, authority.CapKeys) ||
		hasCap(in.Confer, authority.CapPermanentKeys) ||
		hasCap(in.Confer, authority.CapLongTermKeys) ||
		hasCap(in.Confer, authority.CapIdentityHandle) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "apply role conferred identity or long-term key capability"
		return base
	}
	ok, err := authority.Allows(authority.RoleApply, authority.CapIdentityKeys)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows identity_keys for apply"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "apply lacks identity_keys in inventory and conferral"
	return base
}

func negApplyPath(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-APPLY-PATH", Platform: plat, Control: "arbitrary_path_lookup",
	}
	if in.Role != authority.RoleApply {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-apply only"
		return base
	}
	if hasCap(in.Confer, authority.CapArbitraryPathLookup) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "apply role conferred arbitrary_path_lookup"
		return base
	}
	ok, err := authority.Allows(authority.RoleApply, authority.CapArbitraryPathLookup)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows arbitrary_path_lookup for apply"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "apply lacks arbitrary_path_lookup in inventory and conferral"
	return base
}

func negPlanWrite(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-PLAN-WRITE", Platform: plat, Control: "filesystem_writes",
	}
	if in.Role != authority.RolePlan {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-plan only"
		return base
	}
	if hasCap(in.Confer, authority.CapFilesystemWrites) ||
		hasCap(in.Confer, authority.CapArchiveRoots) ||
		hasCap(in.Confer, authority.CapArchiveDescriptors) ||
		hasCap(in.Confer, authority.CapArchives) ||
		hasArchiveSlot(in.SlotKinds) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "plan role conferred filesystem write or archive slot"
		return base
	}
	ok, err := authority.Allows(authority.RolePlan, authority.CapFilesystemWrites)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows filesystem_writes for plan"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "plan lacks filesystem_writes in inventory and conferral"
	return base
}

func negAuditDecide(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-AUDIT-DECIDE", Platform: plat, Control: "operation_decisions",
	}
	if in.Role != authority.RoleAudit {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-audit only"
		return base
	}
	if hasCap(in.Confer, authority.CapOperationDecisions) ||
		hasCap(in.Confer, authority.CapPolicyDecisions) ||
		hasCap(in.Confer, authority.CapAuthorizationPolicy) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "audit role conferred decision capability"
		return base
	}
	ok, err := authority.Allows(authority.RoleAudit, authority.CapOperationDecisions)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows operation_decisions for audit"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "audit lacks operation_decisions in inventory and conferral"
	return base
}

func negJournalNet(plat string, in RoleProbeInput) Finding {
	base := Finding{
		ID: "NEG-JOURNAL-NET", Platform: plat, Control: "network",
	}
	if in.Role != authority.RoleJournal {
		base.Status = StatusSkipped
		base.Detail = "probe applies to integrisd-journal only"
		return base
	}
	if hasCap(in.Confer, authority.CapNetwork) ||
		hasCap(in.Confer, authority.CapNetworkSockets) ||
		hasCap(in.Confer, authority.CapNetworkAcceptLoop) {
		base.Status = StatusUnexpectedAllow
		base.Detail = "journal role conferred network capability"
		return base
	}
	ok, err := authority.Allows(authority.RoleJournal, authority.CapNetwork)
	if err != nil || ok {
		base.Status = StatusUnexpectedAllow
		base.Detail = "inventory allows network for journal"
		return base
	}
	base.Status = StatusDeniedExpected
	base.Detail = "journal lacks network in inventory and conferral"
	return base
}

func hasCap(cs []authority.Capability, want authority.Capability) bool {
	for _, c := range cs {
		if c == want {
			return true
		}
	}
	return false
}

func hasArchiveSlot(kinds []string) bool {
	for _, k := range kinds {
		switch k {
		case "archive_root", "staging_root", "quarantine_root":
			return true
		}
	}
	return false
}

// ParseCapList splits a comma-separated capability env list.
func ParseCapList(s string) []authority.Capability {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]authority.Capability, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, authority.Capability(p))
	}
	return out
}

// ParseSlotKindList splits a comma-separated descriptor-kind env list.
func ParseSlotKindList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
