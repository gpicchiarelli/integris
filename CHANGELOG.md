# Changelog

All notable project changes will be recorded here. The format follows Keep a
Changelog; versioning will follow Semantic Versioning after compatibility policy
is accepted.

## [Unreleased]

### Added

- M1 draft IPs: path grammar/resolution, journal codec envelope, deterministic
  planner, idempotent crash recovery;
- M1 reference kernels under `internal/{path,codec,journal,plan,recovery}`;
- Unix `openat`/`O_NOFOLLOW` path adapter (`golang.org/x/sys`) with platform tests;
- real-filesystem recovery PersistIO and immutable configuration kernel;
- resource admission budgets and destructive-operation quarantine gates;
- filesystem capability preflight (no silent loss) and FS quarantine moves;
- Unix empirical capability probes and renameat exclusive quarantine;
- machine-checkable process authority inventory and verify-config CLI;
- redacted observability events and bounded local IPC frame codec (M2 prelude);
- session state machine refined from formal/session (proto preflight);
- draft IP-A-0002 for local IPC and IP-C-0001 provisional SHA-256 commitments;
- draft IP-P-0001 wire protocol frame widths; HMAC on authenticated IPC channels;
- `internal/protocol` frame codec and engineering release-digest manifest tool;
- M2 prelude `internal/supervisor` grant planner against authority inventory;
- provisional `internal/crypto` HKDF/transcript helpers and supervisor IPC fabric;
- sealed child launch tokens with descriptor slots (no OS spawn yet);
- Unix socketpair IPC fabric and platform confinement discovery scaffold;
- session negotiation transcript binding (provisional);
- engineering module inventory in `integris-release-digest`;
- recovery/session optional observability event emission;
- protocol frame fuzz in CI (PR short + weekly);
- M1 e2e pipeline tests (plan→journal→recovery, session+path, quarantine AT);
- transaction conformance tests mapped to TLA+ abstract flags;
- `integris-evidence` campaign producer and initial `evidence/` artifacts;
- CI short fuzz and weekly fuzz for path/codec/journal kernels;
- produced evidence EVD-JOURNAL-001 and EVD-PLAN-001;

### Previously

- M0 assurance baseline with scope, criticality, lifecycle, governance, release,
  supply-chain, platform, and retirement policies;
- machine-readable requirements, hazards, threats, verification, and evidence;
- strict assurance validator and generated traceability matrix;
- protocol, cryptography, journal, transaction, path, filesystem, deletion,
  configuration, and observability specifications;
- TLA+ transaction and session models;
- pinned least-privilege CI, CodeQL, dependency review, and scheduled fuzzing;
- BSD 3-Clause license.
