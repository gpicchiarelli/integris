// Command integris-evidence runs kernel test campaigns and writes evidence
// manifests under evidence/<area>/. A written file is an artifact; promoting
// assurance/evidence.json to status "produced" remains a separate review step.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type manifest struct {
	EvidenceID  string            `json:"evidence_id"`
	Revision    string            `json:"source_revision"`
	ProducedAt  string            `json:"produced_at"`
	GoVersion   string            `json:"go_version"`
	Platform    string            `json:"platform"`
	Commands    []commandResult   `json:"commands"`
	ArtifactSHA string            `json:"self_digest_note"`
	Residual    []string          `json:"residual_gaps"`
	Extra       map[string]string `json:"extra,omitempty"`
}

type commandResult struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout_tail"`
	Digest   string `json:"stdout_sha256"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if err := run(*root); err != nil {
		fmt.Fprintf(os.Stderr, "integris-evidence: %v\n", err)
		os.Exit(1)
	}
}

func run(root string) error {
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	rev, err := gitOutput(abs, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	rev = strings.TrimSpace(rev)

	campaigns := []struct {
		id       string
		dir      string
		file     string
		commands [][]string
		residual []string
	}{
		{
			id:   "EVD-PATH-001",
			dir:  "evidence/path",
			file: "EVD-PATH-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/path/", "-count=1"},
				{"go", "test", "./internal/path/", "-fuzz=FuzzPathComponent", "-fuzztime=10s"},
				{"go", "test", "./internal/path/", "-fuzz=FuzzPathSequence", "-fuzztime=5s"},
			},
			residual: []string{
				"independent security review of evidence not recorded",
				"FreeBSD/OpenBSD empirical openat campaigns not yet run in CI",
				"VER-PATH-001 remains planned until independent review closes",
			},
		},
		{
			id:   "EVD-JOURNAL-001",
			dir:  "evidence/journal",
			file: "EVD-JOURNAL-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/journal/...", "-count=1"},
				{"go", "test", "./internal/codec/", "-count=1"},
				{"go", "test", "./internal/journal/", "-fuzz=FuzzReadPrefix", "-fuzztime=10s"},
				{"go", "test", "./internal/codec/", "-fuzz=FuzzDecodeRecord", "-fuzztime=10s"},
			},
			residual: []string{
				"independent assurance review of this artifact still required for release use",
			},
		},
		{
			id:   "EVD-PLAN-001",
			dir:  "evidence/planner",
			file: "EVD-PLAN-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/plan/", "-count=1"},
			},
			residual: []string{
				"capability-id registry still provisional (IP-S-0002 dissent)",
				"independent technical review of evidence not recorded",
			},
		},
		{
			id:   "EVD-RECOVERY-001",
			dir:  "evidence/recovery",
			file: "EVD-RECOVERY-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/recovery/", "-count=1"},
			},
			residual: []string{
				"independent assurance review of evidence not recorded",
			},
		},
		{
			id:   "EVD-TXN-001",
			dir:  "evidence/transaction",
			file: "EVD-TXN-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/recovery/", "-count=1", "-run", "Conformance"},
				{"go", "test", "./internal/e2e/", "-count=1", "-run", "PlanJournalRecover"},
			},
			residual: []string{
				"TLC does not prove Go; see internal/recovery/README.md",
				"independent security review of evidence not recorded",
				"VER-TXN-001 remains planned until review closes",
			},
		},
		{
			id:   "EVD-CONFIG-001",
			dir:  "evidence/configuration",
			file: "EVD-CONFIG-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/config/", "-count=1"},
			},
			residual: []string{
				"schema still M1 MVP subset of configuration.md",
				"independent security review of evidence not recorded",
			},
		},
		{
			id:   "EVD-RESOURCE-001",
			dir:  "evidence/resource",
			file: "EVD-RESOURCE-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/resource/", "-count=1"},
			},
			residual: []string{
				"system-level saturation (fd/disk/CPU) pending platform harness",
				"independent security review of evidence not recorded",
			},
		},
		{
			id:   "EVD-DELETE-001",
			dir:  "evidence/deletion",
			file: "EVD-DELETE-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/deletion/", "-count=1"},
			},
			residual: []string{
				"independent security review required for IC-1",
				"VER-DELETE-001 remains planned until review closes",
			},
		},
		{
			id:   "EVD-FS-001",
			dir:  "evidence/platform/filesystem",
			file: "EVD-FS-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/fsmodel/", "-count=1"},
			},
			residual: []string{
				"ACL/xattr/sparse/resource-fork probes still UNKNOWN placeholders",
				"FreeBSD/OpenBSD CI probe matrix not yet scheduled",
				"independent technical review of evidence not recorded",
				"VER-FS-001 remains planned until review closes",
			},
		},
		{
			id:   "EVD-ARCH-001",
			dir:  "evidence/platform/authority",
			file: "EVD-ARCH-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/authority/", "-count=1"},
				{"go", "test", "./internal/supervisor/", "-count=1"},
				{"go", "test", "./internal/crypto/", "-count=1"},
				{"go", "test", "./internal/confine/", "-count=1"},
				{"go", "test", "./internal/launcher/", "-count=1"},
			},
			residual: []string{
				"session AEAD + mutual HMAC peer/archive-auth engineering-only (IP-C-0002); Noise/TLS/PQ deferred",
				"engineering: Landlock/unveil/Seatbelt path allow-roots for Apply/Index via Runtime.AllowRoots; role-net deny; Capsicum fd-only",
				"NEG-FS/FS-READ/FS-PATH/FS-WRITE/EXEC/PTRACE/ROLE-NET + role-semantic NEG-* including auth/index/apply/parser/journal/audit/net MustNot via role stub",
				"MAC key via SCM_RIGHTS default (sealed memfd/anon-unlinked FD); KeyViaExtraFiles opts into legacy fd4",
				"broader path allow-lists beyond archive caps; FreeBSD conferred directory FDs still open",
				"Runtime.RestartChild + RestartPair (KeyViaExtraFiles dual-live); in-place peer FD rebind still open",
				"independent cryptography/security review required for IC-1",
				"VER-PROTO-001 / VER-ARCH-001 remain planned",
			},
		},
		{
			id:   "EVD-PROTO-001",
			dir:  "evidence/protocol",
			file: "EVD-PROTO-001-campaign.json",
			commands: [][]string{
				{"go", "test", "./internal/session/", "-count=1"},
				{"go", "test", "./internal/protocol/", "-count=1"},
				{"go", "test", "./internal/crypto/", "-count=1"},
			},
			residual: []string{
				"provisional AEAD + mutual HMAC peer/archive-auth (IP-C-0002); Noise/TLS/PQ pending superseding IP-C",
				"independent cryptography review required",
				"VER-PROTO-001 remains planned until crypto review",
			},
		},
		{
			id:   "EVD-RELEASE-001",
			dir:  "evidence/releases",
			file: "EVD-RELEASE-001-campaign.json",
			commands: [][]string{
				{"go", "run", "./cmd/integris-release-digest", "-root", "."},
			},
			residual: []string{
				"engineering manifest only — not an independent two-party rebuild",
				"no SBOM/SLSA/signatures",
				"VER-RELEASE-001 remains planned",
			},
		},
	}

	for _, c := range campaigns {
		m := manifest{
			EvidenceID: c.id,
			Revision:   rev,
			ProducedAt: time.Now().UTC().Format(time.RFC3339),
			GoVersion:  runtime.Version(),
			Platform:   runtime.GOOS + "/" + runtime.GOARCH,
			Residual:   c.residual,
			Extra: map[string]string{
				"producer": "integris-evidence",
			},
		}
		for _, args := range c.commands {
			cr, err := runCmd(abs, args)
			if err != nil {
				return fmt.Errorf("%s: %w", c.id, err)
			}
			m.Commands = append(m.Commands, cr)
			if cr.ExitCode != 0 {
				return fmt.Errorf("%s: command failed: %s (exit %d)", c.id, strings.Join(args, " "), cr.ExitCode)
			}
		}
		m.ArtifactSHA = "sha256 of this JSON file after write; see sibling .sha256"
		outDir := filepath.Join(abs, c.dir)
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
		outPath := filepath.Join(outDir, c.file)
		raw, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(outPath, raw, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		if err := os.WriteFile(outPath+".sha256", []byte(digest+"  "+c.file+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%s)\n", filepath.Join(c.dir, c.file), digest)
	}
	return nil
}

func runCmd(dir string, args []string) (commandResult, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	out, err := cmd.CombinedOutput()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			return commandResult{}, err
		}
	}
	sum := sha256.Sum256(out)
	tail := string(out)
	if len(tail) > 4000 {
		tail = tail[len(tail)-4000:]
	}
	return commandResult{
		Command:  strings.Join(args, " "),
		ExitCode: exit,
		Stdout:   tail,
		Digest:   hex.EncodeToString(sum[:]),
	}, nil
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}
