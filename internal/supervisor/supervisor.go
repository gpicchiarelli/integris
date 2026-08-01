// Package supervisor plans child role grants for the M2 privilege-separated
// runtime. It does not spawn processes; it only validates conferred capability
// sets against the authority inventory (IP-A-0001 / INT-IC1-0001).
package supervisor

import (
	"fmt"
	"sort"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// ChildSpec describes one intended child process grant.
type ChildSpec struct {
	Role        authority.ProcessRole
	Confer      []authority.Capability
	IPCPeers    []authority.ProcessRole // allowed remote IPC peers
}

// Plan is a validated supervisor launch plan.
type Plan struct {
	Children []ChildSpec
}

// Error is a typed supervisor planning failure.
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

func fail(code, msg string) error { return &Error{Code: code, Message: msg} }

// BuildPlan validates children against the authority inventory and returns a
// sorted immutable plan. Empty Confer is rejected (explicit grants only).
func BuildPlan(children []ChildSpec) (Plan, error) {
	var zero Plan
	if len(children) == 0 {
		return zero, fail("empty", "no children")
	}
	seen := map[authority.ProcessRole]struct{}{}
	out := make([]ChildSpec, 0, len(children))
	for _, c := range children {
		if c.Role == "" {
			return zero, fail("role", "empty child role")
		}
		if _, ok := seen[c.Role]; ok {
			return zero, fail("duplicate", "duplicate role "+string(c.Role))
		}
		seen[c.Role] = struct{}{}
		if len(c.Confer) == 0 {
			return zero, fail("confer", string(c.Role)+": empty capability grant")
		}
		if err := authority.DeniedProbe(c.Role, c.Confer); err != nil {
			return zero, fail("denied", err.Error())
		}
		// Every conferred capability must be an explicit MayHold.
		for _, cap := range c.Confer {
			ok, err := authority.Allows(c.Role, cap)
			if err != nil {
				return zero, err
			}
			if !ok {
				return zero, fail("denied", fmt.Sprintf("%s cannot hold %s", c.Role, cap))
			}
		}
		for _, peer := range c.IPCPeers {
			if peer == c.Role {
				return zero, fail("ipc", "IPC peer cannot be self")
			}
			if peer == "" {
				return zero, fail("ipc", "empty IPC peer")
			}
		}
		cp := ChildSpec{
			Role:     c.Role,
			Confer:   append([]authority.Capability{}, c.Confer...),
			IPCPeers: append([]authority.ProcessRole{}, c.IPCPeers...),
		}
		sort.Slice(cp.Confer, func(i, j int) bool { return cp.Confer[i] < cp.Confer[j] })
		sort.Slice(cp.IPCPeers, func(i, j int) bool { return cp.IPCPeers[i] < cp.IPCPeers[j] })
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return Plan{Children: out}, nil
}

// MinimalRuntimePlan returns a canonical M2-shaped grant set for all nine roles
// using each role's MayHold inventory (no extras).
func MinimalRuntimePlan() (Plan, error) {
	var kids []ChildSpec
	for _, e := range authority.Inventory() {
		peers := defaultPeers(e.Role)
		kids = append(kids, ChildSpec{Role: e.Role, Confer: append([]authority.Capability{}, e.MayHold...), IPCPeers: peers})
	}
	return BuildPlan(kids)
}

func defaultPeers(role authority.ProcessRole) []authority.ProcessRole {
	switch role {
	case authority.RoleSupervisor:
		return []authority.ProcessRole{authority.RoleNet, authority.RoleAuth, authority.RoleJournal, authority.RoleAudit}
	case authority.RoleNet:
		return []authority.ProcessRole{authority.RoleSupervisor, authority.RoleParser, authority.RoleAuth}
	case authority.RoleAuth:
		return []authority.ProcessRole{authority.RoleSupervisor, authority.RoleNet, authority.RolePlan, authority.RoleApply}
	case authority.RoleParser:
		return []authority.ProcessRole{authority.RoleNet, authority.RolePlan}
	case authority.RoleIndex:
		return []authority.ProcessRole{authority.RolePlan, authority.RoleApply}
	case authority.RolePlan:
		return []authority.ProcessRole{authority.RoleAuth, authority.RoleApply, authority.RoleParser}
	case authority.RoleApply:
		return []authority.ProcessRole{authority.RoleAuth, authority.RolePlan, authority.RoleJournal}
	case authority.RoleJournal:
		return []authority.ProcessRole{authority.RoleApply, authority.RoleAudit, authority.RoleSupervisor}
	case authority.RoleAudit:
		return []authority.ProcessRole{authority.RoleJournal, authority.RoleSupervisor}
	default:
		return nil
	}
}
