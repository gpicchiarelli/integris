package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const testChildEnv = "INTEGRIS_TEST_CHILD"

// InTestSubprocess isolates process-wide test side effects (e.g. unix.CapEnter)
// in a child re-exec of the current test binary (IP-A-0003: os/exec only here).
//
// Parent: re-runs only t.Name(), waits, fails t on child error, returns false.
// Child (INTEGRIS_TEST_CHILD=1): returns true so the caller runs the test body.
// CapEnter tests must use CapEnterTempDir instead of t.TempDir for any dirs
// needed after unix.CapEnter.
func InTestSubprocess(t *testing.T) bool {
	t.Helper()
	if os.Getenv(testChildEnv) == "1" {
		return true
	}

	args := append([]string{"-test.run", fmt.Sprintf("^%s$", t.Name())}, forwardedTestArgs()...)
	cmd := exec.Command(os.Args[0], args...) // #nosec G702 -- intentional re-exec of the test binary
	cmd.Env = append(os.Environ(), testChildEnv+"=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("subprocess %s: %v", t.Name(), err)
	}
	return false
}

// CapEnterTempDir returns a temporary directory for CapEnter subprocess tests.
// It does not register t.Cleanup: after unix.CapEnter, ambient /tmp access is
// denied and cleanup would fail. The child process exits soon; orphaned dirs are OK in CI.
func CapEnterTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "integris-capenter-*")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func forwardedTestArgs() []string {
	var out []string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-test.") {
			continue
		}
		if a == "-test.run" || strings.HasPrefix(a, "-test.run=") {
			if a == "-test.run" && i+1 < len(args) {
				i++
			}
			continue
		}
		out = append(out, a)
		if strings.Contains(a, "=") {
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
			out = append(out, args[i])
		}
	}
	return out
}
