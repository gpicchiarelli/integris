//go:build openbsd

package confine

import (
	"strings"
	"testing"

	"github.com/gpicchiarelli/integris/internal/authority"
)

func TestM5iOpenBSDPromisesRoleParameterized(t *testing.T) {
	cases := []struct {
		role        authority.ProcessRole
		mustHave    []string
		mustNotHave []string
	}{
		{
			role:        authority.RoleNet,
			mustHave:    []string{"stdio", "rpath", "unix", "sendfd", "recvfd", "proc", "inet"},
			mustNotHave: []string{"wpath", "cpath", "exec", "dns", "tmppath"},
		},
		{
			role:        authority.RoleParser,
			mustHave:    []string{"stdio", "rpath", "unix", "sendfd", "recvfd", "proc"},
			mustNotHave: []string{"wpath", "cpath", "inet", "exec", "dns"},
		},
		{
			role:        authority.RoleIndex,
			mustHave:    []string{"stdio", "rpath", "unix", "sendfd", "recvfd", "proc"},
			mustNotHave: []string{"wpath", "cpath", "inet", "exec"},
		},
		{
			role:        authority.RoleApply,
			mustHave:    []string{"stdio", "rpath", "wpath", "cpath", "fattr", "flock", "unix", "sendfd", "recvfd", "proc"},
			mustNotHave: []string{"inet", "exec", "dns", "tmppath"},
		},
		{
			role:        authority.RoleJournal,
			mustHave:    []string{"stdio", "rpath", "wpath", "cpath", "fattr", "flock", "unix", "proc"},
			mustNotHave: []string{"inet", "exec"},
		},
	}
	for _, tc := range cases {
		got := openbsdPromises(tc.role)
		for _, p := range tc.mustHave {
			if !containsPromise(got, p) {
				t.Errorf("%s: missing %q in %q", tc.role, p, got)
			}
		}
		for _, p := range tc.mustNotHave {
			if containsPromise(got, p) {
				t.Errorf("%s: unexpected %q in %q", tc.role, p, got)
			}
		}
	}
}

func containsPromise(promises, want string) bool {
	for _, p := range strings.Fields(promises) {
		if p == want {
			return true
		}
	}
	return false
}
