# Changelog

All notable project changes will be recorded here. The format follows Keep a
Changelog; versioning will follow Semantic Versioning after compatibility policy
is accepted.

## [Unreleased]

### Added

- **INT-IC4-0001**: exhaustive native platform optimization invariant — every
  declared OS must use qualifying stable native I/O, cloning, notification,
  durability, and confinement facilities; portable LCD paths are degraded mode
  only (`docs/specifications/platform-optimization.md`, VER-PERF-001 planned);
- `NOTICE` and `TRADEMARKS.md`: copyright holders, Integris mark limits, and
  nominative third-party mark acknowledgments (Apple, FreeBSD, Linux, OpenBSD,
  Go, TLA+, and related platform facilities);
- expanded GitHub Actions surface: staticcheck/gosec, OSV, Trivy, Semgrep,
  Scorecard, gitleaks, SBOM (CycloneDX/Syft), reproducible dual-build digests
  with attestations, FreeBSD VM tests, macOS cgo Seatbelt, cross-compile matrix
  for Linux/Darwin/FreeBSD/OpenBSD, coverage artifacts, evidence regeneration,
  license inventory, workflow lint (actionlint/zizmor), typos, Markdown link
  check, EditorConfig hygiene, dependency-graph submission, stale bot, and PR
  path labeler; Dependabot grouping for Go/`github-actions`;
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
- draft IP-A-0003 isolated launcher; `internal/launcher` + role stub (engineering);
- wire protocol session Driver; MAC key conferred via pipe fd (not env);
- Linux Landlock + seccomp exec/ptrace denylist + no_new_privs; OpenBSD pledge;
  FreeBSD Capsicum + cap_rights_limit; in-child NEG-FS/EXEC/PTRACE probes via role stub;
- role-semantic NEG-NET-ARCHIVE / NEG-PARSER-NET conferral probes + ValidateSlots;
- role-semantic NEG-PLAN-WRITE / NEG-AUDIT-DECIDE / NEG-JOURNAL-NET conferral probes;
- Darwin Seatbelt `sandbox_init` engineering apply (cgo; not App Sandbox equivalence);
- role-parameterized OS network denials (`ApplyEngineering(role)` + `NEG-ROLE-NET`);
- Darwin Seatbelt deny ambient path reads + `NEG-FS-READ` (parity with Landlock/unveil/Capsicum);
- `supervisor.Runtime.RestartChild` with `SocketFabric.ReplacePair` for engineering child respawn;
- Apply/Index path allow-roots (`ApplyEngineeringOpts` + `NEG-FS-PATH`; Seatbelt/Landlock/unveil);
- Index readonly allow-root write denial (`NEG-FS-WRITE`) via supervised Runtime spawn;
- `NEG-AUTH-ACCEPT` conferral probe for auth `network_accept_loop` MustNot;
- Auth MustNot triad complete (`NEG-AUTH-CONTENTS`, `NEG-AUTH-PUB`);
- Index MustNot probes (`NEG-INDEX-PUB`, `NEG-INDEX-DELETE`);
- Apply MustNot probes (`NEG-APPLY-KEYS`, `NEG-APPLY-PATH`);
- Parser MustNot triad complete (`NEG-PARSER-KEYS`, `NEG-PARSER-ARCHIVES`);
- Journal MustNot triad complete (`NEG-JOURNAL-POLICY`, `NEG-JOURNAL-MUTATE`);
- Audit MustNot triad complete (`NEG-AUDIT-ARCHIVES`, `NEG-AUDIT-SECRETS`);
- Net MustNot triad complete (`NEG-NET-KEYS`, `NEG-NET-JOURNAL`);
- Plan MustNot triad complete (`NEG-PLAN-KEYS`, `NEG-PLAN-NET`);
- Supervisor MustNot triad complete (`NEG-SUP-PARSER`, `NEG-SUP-TRAVERSE`, `NEG-SUP-KEYS`);
- Journal `CrashSegment` FailAt for `J-APPEND-PRE/MID/POST` + `J-META-POST` on FileSegment with Recover round-trip;
- Recovery-side P-* FilePersist FailAt×Recover (`P-STAGE-CREATE/SYNC`, `P-PUBLISH-RENAME/DIRSYNC`, `P-CONFIRM-PRE/POST`);
- Apply-side `FilePublisher` (stage→sync→rename→dirsync FailAt + Observation→Recover);
- OS SIGKILL harness via `integris-crash-stub` + `FilePublisher.KillAt` + `launcher.RunEngineering`;
- Wire `TypeNegotiateOffer` body encodes versions + crypto-suite IDs (`EncodeNegotiateOffer`);
- Wire `TypeNegotiateAccept` body encodes selected version + suite (`EncodeNegotiateAccept` / `ConfirmAccept`);
- `supervisor.Runtime.AllowRoots` forwarded through `StartChild` for supervised spawn probes;
- `Runtime.StartPair`/`RestartPair` with stub initiate mode (KeyViaExtraFiles dual-live edges);
- draft IP-C-0002 provisional ChaCha20-Poly1305 for sealed TypeData;
- session crypto-suite allow-list + transcript-bound traffic key install;
- provisional HMAC peer-auth proof over negotiation transcript (`AuthenticateProof`);
- mutual `i2r`+`r2i` peer-auth before `PEER_AUTHENTICATED` (Session.tla + Driver);
- provisional HMAC archive-authorization proof over post-peer-auth transcript;
- sealed MAC key conferral: Linux memfd seals; other Unix anon-unlinked FD (IP-A-0003);
- SCM_RIGHTS MAC key conferral as default ABI (`KeyViaExtraFiles` opts into legacy fd4);
- `supervisor.Runtime` multi-child engineering spawn helper;
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
