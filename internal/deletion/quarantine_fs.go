package deletion

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/platform"
)

// ExecuteQuarantineMove renames source to quarantine path under the same root
// directory after a successful Evaluate decision. It refuses to replace an
// existing quarantine object and never performs permanent deletion.
//
// root is an already-authorized archive/quarantine workspace on one volume.
// sourceName and quarantineName are single path components (no separators).
func ExecuteQuarantineMove(root string, decision Decision, qp QuarantinePlan) error {
	if !decision.Allowed {
		return stop("decision", "quarantine not allowed: "+decision.Reason)
	}
	if !decision.PermanentDisabled {
		return stop("policy", "permanent deletion path is disabled")
	}
	if err := validateComponent(qp.SourceName); err != nil {
		return err
	}
	if err := validateComponent(qp.QuarantineName); err != nil {
		return err
	}
	src := filepath.Join(root, string(qp.SourceName))
	dstDir := filepath.Join(root, "quarantine")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return stop("io", err.Error())
	}
	dst := filepath.Join(dstDir, string(qp.QuarantineName))
	if _, err := os.Lstat(dst); err == nil {
		return stop("collision", "quarantine object already exists")
	} else if !os.IsNotExist(err) {
		return stop("io", err.Error())
	}
	if _, err := os.Lstat(src); err != nil {
		return stop("io", fmt.Sprintf("source: %v", err))
	}
	if err := os.Rename(src, dst); err != nil {
		return stop("io", err.Error())
	}
	if err := syncDir(dstDir); err != nil {
		return stop("io", "sync quarantine: "+err.Error())
	}
	if err := syncDir(root); err != nil {
		return stop("io", "sync root: "+err.Error())
	}
	return nil
}

func validateComponent(name []byte) error {
	if len(name) == 0 {
		return stop("name", "empty component")
	}
	for _, c := range name {
		if c == 0 || c == '/' || c == '\\' {
			return stop("name", "invalid component byte")
		}
	}
	if string(name) == "." || string(name) == ".." {
		return stop("name", "dot components forbidden")
	}
	return nil
}

func syncDir(path string) error {
	return platform.SyncDir(path)
}
