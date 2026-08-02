package confine

import (
	"runtime"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// RequireAmbientRoleNetDenied fails closed when ambient AF_INET remains
// allowed after apply for roles that must not hold CapNetworkSockets (M4d).
// DeniedExpected or Skipped succeed (Skipped covers CapNetwork holders and
// unsupported OS). FreeBSD is skipped entirely (M3s residual: CapEnter leaves
// sockets; jail ip-disable conflicts with allow-root CapRightsLimit).
func RequireAmbientRoleNetDenied(role authority.ProcessRole) error {
	if runtime.GOOS == "freebsd" {
		return nil
	}
	return RequireAmbientRoleNetFinding(NegativeRoleNet(role))
}
