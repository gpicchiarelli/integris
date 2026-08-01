package confine

import (
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/authority"
)

// ArchiveFSMode is the ambient filesystem access an engineering child may hold
// under conferred allow-roots (empty allow-list remains deny-all).
type ArchiveFSMode int

const (
	ArchiveFSNone ArchiveFSMode = iota
	ArchiveFSReadonly
	ArchiveFSReadWrite
)

// RoleMayHoldNetwork reports whether the authority inventory allows the role to
// hold CapNetworkSockets. Unknown roles and inventory errors fail closed.
func RoleMayHoldNetwork(role authority.ProcessRole) bool {
	ok, err := authority.Allows(role, authority.CapNetworkSockets)
	return err == nil && ok
}

// RoleArchiveFSMode returns the ambient archive-path mode for role.
// CapArchiveRoots → read/write; CapReadonlyArchiveRoot → read-only; else none.
func RoleArchiveFSMode(role authority.ProcessRole) ArchiveFSMode {
	if ok, err := authority.Allows(role, authority.CapArchiveRoots); err == nil && ok {
		return ArchiveFSReadWrite
	}
	if ok, err := authority.Allows(role, authority.CapReadonlyArchiveRoot); err == nil && ok {
		return ArchiveFSReadonly
	}
	return ArchiveFSNone
}

// ApplyOptions parameterizes engineering OS apply beyond role defaults.
type ApplyOptions struct {
	// AllowRoots are absolute directories permitted under RoleArchiveFSMode.
	// Ignored when the role's archive mode is ArchiveFSNone.
	AllowRoots []string
}

// NormalizeAllowRoots EvalSymlinks absolute directory roots; rejects non-abs.
func NormalizeAllowRoots(roots []string) ([]string, error) {
	if len(roots) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(roots))
	seen := map[string]struct{}{}
	for _, r := range roots {
		if r == "" {
			continue
		}
		if !filepath.IsAbs(r) {
			return nil, fail("roots", "allow root must be absolute: "+r)
		}
		resolved, err := filepath.EvalSymlinks(r)
		if err != nil {
			return nil, fail("roots", err.Error())
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	return out, nil
}

func fail(code, msg string) error {
	return &Error{Code: code, Message: msg}
}

// Error is a typed confine failure (roots validation, etc.).
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
