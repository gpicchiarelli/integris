//go:build unix

// Engineering crash stub: run FilePublisher.Publish or journal CrashSegment
// append with KillAt at an IP-S-0003 catalog label (OS SIGKILL harness).
// Not a product daemon.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gpicchiarelli/integris/internal/codec"
	"github.com/gpicchiarelli/integris/internal/journal"
	"github.com/gpicchiarelli/integris/internal/launcher"
	"github.com/gpicchiarelli/integris/internal/recovery"
)

const (
	envCrashMode   = "INTEGRIS_CRASH_MODE"
	envCrashRoot   = "INTEGRIS_CRASH_ROOT"
	envCrashName   = "INTEGRIS_CRASH_NAME"
	envCrashFailAt = "INTEGRIS_CRASH_FAIL_AT"
	envCrashData   = "INTEGRIS_CRASH_DATA"

	modePublish = "publish"
	modeJournal = "journal"
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
	failAt := os.Getenv(envCrashFailAt)
	root := os.Getenv(envCrashRoot)
	if root == "" || failAt == "" {
		return fmt.Errorf("missing %s / %s", envCrashRoot, envCrashFailAt)
	}
	mode := os.Getenv(envCrashMode)
	if mode == "" {
		mode = modePublish
	}
	switch mode {
	case modePublish:
		return runPublish(root, failAt)
	case modeJournal:
		return runJournal(root, failAt)
	default:
		return fmt.Errorf("unknown %s %q", envCrashMode, mode)
	}
}

func runPublish(root, failAt string) error {
	name := os.Getenv(envCrashName)
	if name == "" {
		return fmt.Errorf("missing %s", envCrashName)
	}
	data := os.Getenv(envCrashData)
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

func runJournal(dir, failAt string) error {
	path := filepath.Join(dir, "journal")
	inner, err := journal.OpenFileSegment(path)
	if err != nil {
		return err
	}
	defer inner.Close()

	cs := &journal.CrashSegment{Inner: inner, Dir: dir}
	w, _, err := journal.OpenWriter(cs)
	if err != nil {
		return err
	}
	id := codec.TransactionID{3}
	b := recovery.AuthorizationBinding{
		PlanDigest:             codec.SHA256([]byte("plan")),
		ConfigurationDigest:    codec.SHA256([]byte("cfg")),
		CapabilityVectorDigest: codec.SHA256([]byte("cap")),
		RootIdentity:           codec.SHA256([]byte("root")),
		VolumeIdentity:         codec.SHA256([]byte("vol")),
		AuthDigest:             codec.SHA256([]byte("auth")),
	}
	if _, err := w.Append(id, codec.TypePlanDigest, b.PlanDigest[:]); err != nil {
		return err
	}
	if _, err := w.Append(id, codec.TypeAuthorization, recovery.EncodeAuthorizationPayload(b)); err != nil {
		return err
	}
	if _, err := w.Append(id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressContentReceived)); err != nil {
		return err
	}
	cs.KillAt = failAt
	_, err = w.Append(id, codec.TypeProgress, recovery.EncodeProgressPayload(recovery.ProgressPrepared))
	return err
}
