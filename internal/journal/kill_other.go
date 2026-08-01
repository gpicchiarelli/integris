//go:build !unix

package journal

import "fmt"

func killSelfAt(label string) error {
	return fmt.Errorf("KillAt unsupported on this OS: %s", label)
}
