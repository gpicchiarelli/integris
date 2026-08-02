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
				"J-APPEND + recovery/apply P-* FailAt + OS SIGKILL + Darwin F_FULLFSYNC SyncFile + CloneFile PublishFrom (sparse SEEK + CopyXattr+CopyBSDFlags+CopyACL+CopyResourceFork+CopyTimes/birthtime on degraded copy) complete; Darwin abrupt-detach SyncFile-survive harness complete (unflushed-loss skipped when host flushes .dmg)",
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
				"RLIMIT_NOFILE descriptor saturation harness complete (WithSoftNOFILE)",
				"RLIMIT_FSIZE disk-write saturation harness complete (WithSoftFSIZE → EFBIG; not ENOSPC)",
				"RLIMIT_CPU process CPU-time harness complete (WithSoftCPU → SIGXCPU; not system-wide load)",
				"RLIMIT_NPROC process-count harness complete (WithSoftNPROC → EAGAIN when unprivileged; FreeBSD clamps hard max; euid0 may retain PRIV_PROC_LIMIT)",
				"RLIMIT_AS address/data-space harness complete (WithSoftAS → ENOMEM mmap; Darwin unenforceable; OpenBSD RLIMIT_DATA)",
				"true ENOSPC full-volume harness complete (Darwin hdiutil 2MiB HFS+ image → unix.ENOSPC)",
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
				{"go", "test", "./internal/platform/", "-count=1", "-run", "SendFile"},
				{"go", "test", "./internal/platform/", "-count=1", "-run", "VNode"},
			},
			residual: []string{
				"CapCOW empirical via platform.CloneFile (Darwin clonefile / Linux FICLONE→LOSSLESS; copy→UNREPRESENTABLE)",
				"CapXattr/CapBSDFlags empirical (Setxattr/Getxattr; Darwin/FreeBSD/OpenBSD chflags)",
				"CapSparse/CapResourceFork empirical (SEEK_HOLE/SEEK_DATA; Darwin ..namedfork/rsrc)",
				"CapTimes empirical (Chtimes + Stat Atim/Mtim)",
				"CapACL empirical via platform.ACLRoundTrip (Darwin cgo acl_*; Linux system.posix_acl_access xattr; other ports UNKNOWN)",
				"CopyACL on CloneFile degraded copy (Darwin cgo; Linux posix ACL xattr; clonefile preserves ACL natively)",
				"CopyXattr on CloneFile degraded copy (listxattr/getxattr/setxattr; skips Darwin ACL xattr)",
				"CopyBSDFlags on CloneFile degraded copy (chflags from Stat_t.Flags; Darwin/FreeBSD/OpenBSD)",
				"CopyTimes on CloneFile degraded copy (pre-capture Stat; SyncFile then UtimesNano; Darwin Setattrlist CRTIME)",
				"CopyResourceFork on CloneFile degraded copy (Darwin ..namedfork/rsrc; skips xattr twin)",
				"Sparse-aware CloneFile degraded copy (SEEK_DATA/SEEK_HOLE; Linux copy_file_range then io.Copy fallback)",
				"Sparse-aware CloneFile degraded copy (SEEK_DATA/SEEK_HOLE; io.Copy fallback)",
				"platform.SendFile sendfile(2) socketpair harness (Darwin/Linux/FreeBSD; OpenBSD unavailable)",
				"platform.VNodeWatch kqueue EVFILT_VNODE harness (NOTE_WRITE/DELETE; Linux unavailable)",
				"CapUnicode empirical (NFC/NFD é twin; APFS fold→WRAPPED; preserve→LOSSLESS)",
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
				"engineering: Landlock/unveil/Seatbelt path allow-roots for Apply/Index/Journal/Audit via Runtime.AllowRoots; role-net deny; Capsicum fd-only",
				"engineering: Landlock/unveil/Seatbelt path allow-roots for Apply/Index/Journal/Audit; FreeBSD Capsicum AllowRootFDs claimed in product (M3c)",
				"NEG-CAP-MODE/FS/FS-READ/FS-PATH/FS-WRITE/EXEC/PTRACE/ROLE-NET + role-semantic NEG-* covering complete inventory MustNot for all nine roles via role stub",
				"engineering: Landlock/unveil/Seatbelt path allow-roots for Apply/Index via Runtime.AllowRoots; role-net deny; Capsicum fd-only",
				"NEG-CAP-MODE/FS/FS-READ/FS-PATH/FS-WRITE/EXEC/PTRACE/ROLE-NET + role-semantic NEG-* covering complete inventory MustNot for all nine roles via role stub; hostile IPC refuse matrix (forged MAC/truncation/sequence/role/nonce)",
				"MAC key via SCM_RIGHTS default on dedicated key channel (M2l); KeyViaExtraFiles opts into legacy fd4",
				"Journal/Audit path allow-roots landed; FreeBSD AllowRootFDs claimed (M3c); M3d–M3r openat/CapEnter chain; M3j drain; M3k–M3q release CapMode/rights/ambient FS-read; M3p supervised CapEnter push; M3r StrictLaunch CapEnter RestartOne first cut",
				"broader path allow-lists beyond archive caps still open",
				"Runtime.RestartChild + RestartPair (M2m) + RestartOne (M2n–M3b/M3j exit-drain)",
				"broader path allow-lists beyond archive caps still open",
				"Runtime.RestartChild + RestartPair (M2m) + RestartOne (M2n–M3j/M3r); M3c–M3r CapEnter openat + release self-checks (incl. ambient FS-read) + supervised CapEnter push + StrictLaunch CapEnter RestartOne first cut",
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
				"provisional AEAD + mutual HMAC peer/archive-auth (IP-C-0002); wire NegotiateOffer/Accept + hostile-peer refuse + multi-version happy-path suites; TypeData chunk envelope + TrackDataChunks gap/replay refuse; Noise/TLS/PQ pending superseding IP-C",
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
			if os.Getenv("INTEGRIS_EVIDENCE_SKIP_FUZZ") != "" && commandHasFuzz(args) {
				continue
			}
			cr, err := runCmd(abs, args)
			if err != nil {
				return fmt.Errorf("%s: %w", c.id, err)
			}
			m.Commands = append(m.Commands, cr)
			if cr.ExitCode != 0 {
				return fmt.Errorf("%s: command failed: %s (exit %d)\n%s", c.id, strings.Join(args, " "), cr.ExitCode, cr.Stdout)
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

func commandHasFuzz(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-fuzz=") || a == "-fuzz" {
			return true
		}
	}
	return false
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	return string(out), err
}
