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
