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
// CapEnter tests must also call SkipSubprocessCleanupOnSuccess before CapEnter.
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

// SkipSubprocessCleanupOnSuccess exits a CapEnter subprocess test before t.TempDir
// cleanups run (ambient /tmp access is denied after unix.CapEnter). Call after all
// t.TempDir setup and immediately before unix.CapEnter.
func SkipSubprocessCleanupOnSuccess(t *testing.T) {
	t.Helper()
	if os.Getenv(testChildEnv) != "1" {
		return
	}
	t.Cleanup(func() {
		if !t.Failed() {
			os.Exit(0)
		}
	})
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
