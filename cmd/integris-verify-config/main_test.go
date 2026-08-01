package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyConfigCLI(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.json")
	body := `{
  "schema_version": 1,
  "node_name": "cli-node",
  "max_journal_payload_bytes": 1024,
  "session_timeout_ms": 1000,
  "allow_destructive": false,
  "allow_weak_confinement": false,
  "allow_network_listen": false
}`
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", ".", "-config", cfg)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "digest_sha256=") || !strings.Contains(s, "canonical_json=") {
		t.Fatalf("output=%s", s)
	}
}

func TestVerifyConfigCLIRejectsBad(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(cfg, []byte(`{"schema_version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", ".", "-config", cfg)
	cmd.Dir = "."
	if err := cmd.Run(); err == nil {
		t.Fatal("expected failure")
	}
}
