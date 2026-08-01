package confine

import "github.com/gpicchiarelli/integris/internal/authority"

// RoleMayHoldNetwork reports whether the authority inventory allows the role to
// hold CapNetworkSockets. Unknown roles and inventory errors fail closed.
func RoleMayHoldNetwork(role authority.ProcessRole) bool {
	ok, err := authority.Allows(role, authority.CapNetworkSockets)
	return err == nil && ok
}
