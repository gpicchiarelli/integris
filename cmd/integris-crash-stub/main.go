//go:build unix

// Engineering crash stub: run FilePublisher.Publish with KillAt at a catalog
// label (OS SIGKILL harness for IP-S-0003). Not a product daemon.
package main

import (
	"fmt"
	"os"

	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

const (
	envCrashRoot   = "INTEGRIS_CRASH_ROOT"
	envCrashName   = "INTEGRIS_CRASH_NAME"
	envCrashFailAt = "INTEGRIS_CRASH_FAIL_AT"
	envCrashData   = "INTEGRIS_CRASH_DATA"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "integris-crash-stub: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if os.Getenv(launcher.EnvMode) != launcher.ModeEngineering {
		return fmt.Errorf("refusing non-engineering launch mode")
	}
	root := os.Getenv(envCrashRoot)
	name := os.Getenv(envCrashName)
	failAt := os.Getenv(envCrashFailAt)
	data := os.Getenv(envCrashData)
	if root == "" || name == "" || failAt == "" {
		return fmt.Errorf("missing %s / %s / %s", envCrashRoot, envCrashName, envCrashFailAt)
	}
	if data == "" {
		data = "crash-stub-payload"
	}
	pub, err := recovery.NewFilePublisher(root)
	if err != nil {
		return err
	}
	pub.KillAt = recovery.CrashLabel(failAt)
	pub.ExpectedContent = []byte(data)
	return pub.Publish(name, []byte(data))
}
