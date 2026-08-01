//go:build !darwin && !linux

package platform

import "fmt"

// PreferredCloneMechanism is the clone primitive for this build (portable copy).
func PreferredCloneMechanism() string { return CloneMechanismCopy }

// CloneFile materializes dst from src via exclusive byte copy (degraded mode
// until a native clone adapter is adopted on this OS).
func CloneFile(dst, src string) (mechanism string, err error) {
	if dst == "" || src == "" {
		return "", fmt.Errorf("platform: empty clone path")
	}
	if err := copyFileExclusive(dst, src); err != nil {
		return "", err
	}
	return CloneMechanismCopy, nil
}
