# Changelog

All notable project changes will be recorded here. The format follows Keep a
Changelog; versioning will follow Semantic Versioning after compatibility policy
is accepted.

## [Unreleased]

### Fixed

- Formal models workflow no longer cancels in-flight TLC runs, so a cancelled
  default-branch run cannot leave the README Formal badge stuck on failing.
- `integrisd-auth` once-mode no longer exits immediately after sealing the
  session FD to net (SCM_RIGHTS race that could drop the handoff mid-push).

### Added

- first executable vertical slice: unidirectional local sync
  (`internal/localsync`, `cmd/integris sync`) with deterministic scan/plan,
  staged publish, SHA-256 verify, structured JSON result, and docs in
  `docs/localsync.md`;
- M1b local journal + crash resume: IP-F-0001 segment under
  `destination/.integris/`, plan snapshot, per-op progress, recovery records,
  and resume tests;
- M1c authenticated remote push: `internal/remotesync` + `integris push|serve`
  over IP-P with provisional mutual auth/AEAD (PSK), staging into localsync;
  session `DefaultMaxAccept` for ACTIVE data plane (model bound unchanged);
- M1d chunked remote transfer + mid-file resume: `FileBegin`/`Ack`/`Chunk`/`End`,
  default 256 KiB chunks (`integris push -chunk-size`), durable partials under
  `destination/.integris/recv-partial/`, stage under `recv-stage/`;
  `ResolveRoots` allows source trees under `destination/.integris/`;
- M2a privilege-separated receive: `cmd/integrisd` + `internal/daemon` split
  `integrisd-net` / `integrisd-apply` over INTIPC with sealed push-root FD to net
  and destination allow-roots to apply; docs in `docs/daemon-m2a.md`;
- M2b supervised restart + persistent serve: multi-push accept loops,
  `-max-restarts` pair recovery, ready republish, `Server.Status`;
- M2c auth role: `integrisd-auth` holds push PSK and runs AcceptHandshake;
  sealed session returned to net over IPC+SCM_RIGHTS; net ExtraPeer to apply;
  `AuthNetApplyPlan` for auth-without-parser mode;
- M2d parser role: `integrisd-parser` on the receive data plane between net and
  apply (`AuthParserNetApplyPlan`); validates app messages over INTIPC; no PSK
  and no archive roots in parser;
- M2e audit role: `integrisd-audit` redacted event sink (`AuthParserNetApplyAuditPlan`);
  apply emits best-effort commit events over INTIPC; sink at `.integris/audit.events`;
- M2f journal role: `integrisd-journal` owns `local.jrn` (`AuthParserNetApplyJournalAuditPlan`);
  apply uses `localsync.JournalSession` over INTIPC; audit relays via journal ExtraPeer;
- M2g plan role: `integrisd-plan` between parser and apply
  (`AuthParserNetPlanApplyJournalAuditPlan`); canonicalizes manifests and binds
  the file stream without archive FS access;
- M2h index role: `integrisd-index` between plan and apply
  (`AuthParserNetPlanIndexApplyJournalAuditPlan` default for `integrisd serve`);
  readonly destination Scan at commit; apply skips dest Scan via DestManifest;
- M2i peer PSK allow-list: `integrisd serve -peer-key ID=PATH` + `integris push -peer ID`;
  `INTPEER1` keyring in auth; peer prologue + peer-bound MAC;
- M2j peer admit/deny audit: with `-peer-key`, auth ExtraPeer→audit emits
  `auth.peer.admit` / `auth.peer.deny` (opaque peer digest) to `.integris/audit.events`;
- M2k strict launch: `integrisd serve -strict-launch` / `ServeOptions.StrictLaunch`
  requires full role chain, sets `INTEGRIS_LAUNCH_MODE=release`, fails closed if
  confinement APPLY-* is unavailable or skipped;
- M2l SCM-only key conferral: default ExtraFiles is sockets + dedicated key
  channel (fd4); MAC/root/extra keys via `SCM_RIGHTS` on `Handle.KeyChannel`;
  `KeyViaExtraFiles` remains opt-in;
- M2m SCM dual-live: `StartPair` / `RestartPair` work on the default key-channel
  path (no longer require `KeyViaExtraFiles`); ExtraFiles dual-live still tested;
- M2n in-place peer FD rebind: `Runtime.RestartOne` + `ipc.SendPeerFDFile`
  (`PeerFDMagic`) into a surviving dual-live child; stub hold modes;
- M2o daemon RestartOne: M2a (`DisableAuth`) apply exit rebinds into surviving
  net (listen PID/addr unchanged);
- M2p ExtraPeer RestartOne: M2c (`DisableParser`) apply exit rebinds net’s
  ExtraPeer→apply socket; auth + listen survive;
- M2q parser ExtraPeer RestartOne: M2d apply exit rebinds parser→apply; parser
  + net + auth survive; `ServeParserBridgeDyn`;
- M2r M2g plan ExtraPeer restart: apply death respawns apply+journal+audit and
  rebinds plan→apply; plan/parser/net/auth survive; `ServePlanBridgeDyn`;
- M2s M2h index ExtraPeer restart: apply death respawns apply+journal+audit and
  rebinds index→apply; index+upstream survive; `ServeIndexBridgeDyn`;
- M2t M2d parser restart: parser death respawns parser+apply and rebinds net
  ExtraPeer→parser; auth+net survive;
- M2u M2g parser-downstream restart: parser/plan death respawns
  parser→plan→apply→journal→audit and rebinds net ExtraPeer→parser; auth+net
  survive;
- M2v M2h parser-downstream restart: parser/plan/index death respawns
  parser→plan→index→apply→journal→audit and rebinds net ExtraPeer→parser;
  auth+net survive;
- M2w M2c auth primary RestartOne: auth death respawns auth and rebinds net
  primary→auth via `PrimaryPeerFDMagic` demux; net+apply+listen survive;
- M2x/M2y/M2z auth primary RestartOne on M2d/M2g/M2h (shared PSK); same demux;
- M3a M2j auth ExtraPeer RestartOne: with peer keyring, auth death also rebinds
  audit ExtraPeer→auth (`ServeAuditSinkExtraDyn`); audit PID survives;
- M3b M2j audit→auth ExtraPeer RestartOne: apply/audit subtree respawn rebinds
  surviving auth ExtraPeer→audit; auth PID survives;
- M3c FreeBSD allow-root FD product claim: `ClaimChild`/`Confine` adopt
  conferred directory FDs + `LimitAllowRootFDs`; Journal/Audit FreeBSD
  `NEG-FS-WRITE` parity with Apply/Index;
- M3d index `ScanAt` via openat on conferred allow-root FD; `runIndex` wires
  `AllowRootFDs[0]` into `ServeIndexBridge*`;
- M3e apply staging via openat on conferred allow-root FD (`recv-stage` /
  `recv-partial`); `runApply` wires `AllowRootFDs[0]` into `ServeApplyIPC*`;
  commit/`localsync.Sync` publish remains ambient;
- M3f journal reopen via openat on conferred allow-root FD
  (`OpenFileJournalAt` / `OpenFileSegmentAt`); `runJournal` wires
  `AllowRootFDs[0]` into `ServeJournalIPC`;
- M3g apply publish via openat: `ApplyAt` + `Sync` `SourceFD`/`DestFD`
  (ScanAt/ApplyAt/plan snapshot); commit wires stage+dest FDs; stage wipe
  via unlinkat;
- M3h audit sink openat bootstrap (`OpenAuditSinkAt` / `.integris/audit.events`);
  `runAudit` wires `AllowRootFDs[0]`; archive allow-root stays readonly;
- M3i CapEnter receive openat chain proof (stage→ScanAt→journaled publish→audit
  sink); unix + FreeBSD CapEnter tests;
- M3j RestartOne exit-channel drain: `flushExitPending` after cascade waits;
  `armWatcher` suppresses superseded-handle exits;
- M3k FreeBSD CapEnter stub probe `NEG-CAP-MODE` (`cap_getmode`); supervised
  role-stub asserts capability mode after apply;
- M3l journal ambient bootstrap via openat (`BootstrapJournalAt`); `runJournal`
  wires `AllowRootFDs[0]` before CapEnter;
- M3m product CapEnter self-check fail-closed: release-mode `Confine` requires
  FreeBSD capability mode via `RequireCapModeAvailable` / `cap_getmode`;
- M3n product allow-root Capsicum rights fail-closed: release-mode `Confine`
  requires `APPLY-CAP-ALLOW-ROOTS` Available or Skipped
  (`RequireAllowRootLimitFinding`);
- M3o product conferred Capsicum rights fail-closed: `ClaimChild` stores
  `LimitConferredFDs`; release-mode `Confine` requires `APPLY-CAP-RIGHTS`
  Available or Skipped (`RequireConferredLimitFinding`);
- M3p FreeBSD supervised CapEnter push first cut: StrictLaunch Once product
  push under CapEnter; archive-role stub AllowRoots assert
  `|NEG-CAP-MODE:available`;
- M3q product ambient FS-read deny fail-closed: release-mode `Confine`
  requires `NEG-FS-READ` DeniedExpected (`RequireAmbientFSReadDenied`);
  FreeBSD AllowRoots stubs assert ambient deny beside openat path allow;
- M3r FreeBSD StrictLaunch CapEnter RestartOne first cut: persistent serve
  under CapEnter; kill apply; net PID + listen addr survive; second push
  succeeds with M3m–M3q fail-closed confine on replacement children;
- M3s FreeBSD ambient AF_INET residual documented: CapEnter leaves
  `NEG-ROLE-NET` UnexpectedAllow; jail ip-disable rejected for product use
  (conflicts with allow-root `CapRightsLimit`); probe + CapEnter residual test;
- M3t FreeBSD sealed MAC key FD: `CreateKeyFD` via `shm_open2(SHM_ANON)` +
  `F_ADD_SEALS` (`memfd-sealed`); `DISC-KEY-FD` Available; Darwin/OpenBSD
  remain anon-unlinked residual;
- M3u FreeBSD StrictLaunch CapEnter parser-down RestartOne: kill parser after
  first push; net+auth + listen survive; parser→plan→index→apply→journal→audit
  respawn under M3m–M3q fail-closed confine; second push succeeds;
- M3v FreeBSD StrictLaunch CapEnter auth-primary RestartOne: kill auth after
  first push; net + full data plane + listen survive; auth respawns with
  primary peer rebind under M3m–M3q fail-closed confine; second push succeeds;
- M3w FreeBSD StrictLaunch CapEnter M2j auth ExtraPeer RestartOne: peer
  keyring; kill auth after first peer push; data plane + listen survive; auth
  respawns with primary + audit ExtraPeer rebind; ≥2 `auth.peer.admit`;
- M3x FreeBSD StrictLaunch CapEnter M2j audit ExtraPeer RestartOne: peer
  keyring; kill audit after first peer push; auth+upstream + listen survive;
  apply+journal+audit respawn with auth ExtraPeer→audit rebind; ≥2 admits;
- M3y FreeBSD StrictLaunch CapEnter M2j peer-key push: StrictLaunch Once with
  peer keyring under CapEnter; peer push succeeds with journal/audit/plan and
  ≥1 `auth.peer.admit`;
- M3z FreeBSD StrictLaunch CapEnter M2j apply RestartOne: peer keyring; kill
  apply after first peer push; net+auth+index + listen survive;
  apply+journal+audit respawn; ≥2 `auth.peer.admit`;
- M4a FreeBSD StrictLaunch CapEnter M2j parser-down RestartOne: peer keyring;
  kill parser after first peer push; net+auth + listen survive;
  parser→plan→index→apply→journal→audit respawn; ≥2 `auth.peer.admit`;
- M4b FreeBSD StrictLaunch CapEnter M2j peer deny/admit: unknown peer and
  wrong-key rejected without destination mutation; valid peer push admits with
  `auth.peer.deny` + `auth.peer.admit`;
- M4c Darwin/OpenBSD anon key FD residual documented: `CreateKeyFD` stays
  anon-unlinked O_RDONLY; `DISC-KEY-FD` Unavailable; sealed path remains
  Linux/FreeBSD only;
- M4d release ambient ROLE-NET deny (non-FreeBSD): `ChildEnv.Confine` calls
  `RequireAmbientRoleNetDenied` (`NEG-ROLE-NET`) on Linux/Darwin/OpenBSD;
  FreeBSD remains a no-op (M3s CapEnter residual);
- M4e Darwin StrictLaunch Seatbelt push first cut: StrictLaunch Once under
  `sandbox_init` completes push with journal/audit/plan (M3p Darwin parity);
- M4f Darwin StrictLaunch Seatbelt RestartOne apply: kill apply after first
  push; net PID + listen survive; apply+journal+audit respawn; second push
  succeeds (M3r Darwin parity);
- M4g Darwin StrictLaunch Seatbelt parser-down RestartOne: kill parser after
  first push; net+auth + listen survive; parser→plan→index→apply→journal→audit
  respawn; second push succeeds (M3u Darwin parity);
- M4h Darwin StrictLaunch Seatbelt auth-primary RestartOne: kill auth after
  first push; net + data plane + listen survive; auth respawns; second push
  succeeds (M3v Darwin parity);
- M4i Darwin StrictLaunch Seatbelt auth ExtraPeer RestartOne: peer keyring;
  kill auth; data plane + listen survive; auth respawns with ExtraPeer rebind;
  ≥2 `auth.peer.admit` (M3w Darwin parity);
- M4j Darwin StrictLaunch Seatbelt audit ExtraPeer RestartOne: peer keyring;
  kill audit; auth+upstream + listen survive; apply+journal+audit respawn;
  ≥2 `auth.peer.admit` (M3x Darwin parity);
- M4k Darwin StrictLaunch Seatbelt peer-key push: StrictLaunch Once with peer
  keyring under Seatbelt; peer push succeeds with journal/audit/plan and ≥1
  `auth.peer.admit` (M3y Darwin parity);
- M4l Darwin StrictLaunch Seatbelt peer deny/admit: unknown peer and wrong-key
  rejected without destination mutation; valid peer push admits with
  `auth.peer.deny` + `auth.peer.admit` (M4b Darwin parity);
- M4m Darwin StrictLaunch Seatbelt peer apply RestartOne: peer keyring; kill
  apply after first peer push; net+auth+index + listen survive;
  apply+journal+audit respawn; ≥2 `auth.peer.admit` (M3z Darwin parity);
- M4n Darwin StrictLaunch Seatbelt peer parser-down RestartOne: peer keyring;
  kill parser after first peer push; net+auth + listen survive;
  parser→plan→index→apply→journal→audit respawn; ≥2 `auth.peer.admit` (M4a
  Darwin parity);
- mdoc manual pages for all shipped tools plus overview/daemon pages
  (`man/man1`, `man/man7/integris.7`, `man/man8/integrisd.8`) with portable
  `make install-man` / `install` (`PREFIX`, `DESTDIR`, `MANDIR`) and `man-lint`;
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
- Journal/Audit path allow-roots via `RoleArchiveFSMode` (`CapJournalDescriptor` RW /
  `CapReadonlyJournal` RO) + supervised Runtime spawn probes;
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
- OS SIGKILL harness for journal J-* via `CrashSegment.KillAt` + crash-stub `mode=journal`;
- `internal/platform.SyncFile`/`SyncDir` with Darwin `F_FULLFSYNC` (INT-IC4-0001) on journal, recovery, quarantine, and key-FD sync paths;
- Consolidated hostile-peer `protocol.Driver` refuse matrix (`hostile_peer_test.go`);
- Darwin `platform.CloneFile` (`clonefile`) + `FilePublisher.PublishFrom` (copy degraded fallback);
- Linux `platform.CloneFile` (`FICLONE` / reflink) with exclusive-copy degraded fallback;
- Empirical CapCOW probe in `fsmodel.ProbeScratch` via `platform.CloneFile`;
- Multi-version negotiate happy-path suite (`multi_version_test.go`);
- Empirical CapXattr + CapBSDFlags probes in `fsmodel.ProbeScratch`;
- Empirical CapSparse + CapResourceFork probes in `fsmodel.ProbeScratch`;
- Empirical CapTimes probe in `fsmodel.ProbeScratch` (Chtimes round-trip);
- Empirical CapACL probe via Darwin cgo `platform.ACLRoundTrip` (`acl_*`);
- Empirical CapUnicode probe in `fsmodel.ProbeScratch` (NFC/NFD é twin fold vs preserve);
- Darwin `platform.CopyACL` (`acl_get_file`→`acl_set_file`) on CloneFile degraded copy path;
- `platform.CopyXattr` (`listxattr`/`getxattr`/`setxattr`) on CloneFile degraded copy path;
- `platform.CopyBSDFlags` (`chflags` from `Stat_t.Flags`) on CloneFile degraded copy path;
- `platform.CopyTimes` (`Chtimes`) + degraded-copy `SyncFile` then `UtimesNano` (atime-safe) on CloneFile path;
- `platform.CopyResourceFork` (`..namedfork/rsrc`) on CloneFile degraded copy path;
- Sparse-aware CloneFile degraded copy via `SEEK_DATA`/`SEEK_HOLE` (io.Copy fallback);
- Darwin birthtime restore on CloneFile degraded copy (`Setattrlist` `ATTR_CMN_CRTIME`);
- `resource.WithSoftNOFILE` FD saturation harness for EVD-RESOURCE (`RLIMIT_NOFILE`);
- `resource.WithSoftFSIZE` disk-write saturation harness for EVD-RESOURCE (`RLIMIT_FSIZE` → EFBIG);
- `resource.WithSoftCPU` process CPU-time saturation harness for EVD-RESOURCE (`RLIMIT_CPU` → SIGXCPU);
- Darwin true-ENOSPC harness for EVD-RESOURCE (`hdiutil` 2MiB HFS+ image → `unix.ENOSPC`);
- Restrict int64 `Rlimit` helpers to FreeBSD/DragonFly (OpenBSD/NetBSD use uint64 like Linux/Darwin);
- Hostile IPC refuse matrix (`internal/ipc/hostile_test.go`) for IP-A-0002 / VER-ARCH engineering probes;
- TypeData chunk envelope (`offset||length||data`) + `Driver.TrackDataChunks` contiguous resume refuse matrix;
- `resource.WithSoftNPROC` process-count saturation harness for EVD-RESOURCE (`RLIMIT_NPROC` → EAGAIN);
- Linux `copy_file_range` fallback in `copyFileContents` (after sparse SEEK; before `io.Copy`);
- `Runtime.RestartChild` retains `AllowRoots` path probes across respawn;
- Darwin abrupt-detach power-fail harness for EVD-RECOVERY (`SyncFile` survive across `hdiutil` force-detach);
- `platform.SendFile` (`sendfile(2)` to connected socket; socketpair harness; OpenBSD unavailable);
- FreeBSD Capsicum conferred allow-root directory FDs (`INTEGRIS_ALLOW_ROOT_FDS` + `LimitAllowRootFDs` + `NEG-FS-PATH`/`WRITE` via openat);
- `platform.VNodeWatch` kqueue `EVFILT_VNODE` harness (`NOTE_WRITE`/`NOTE_DELETE`; Linux unavailable);
- `resource.WithSoftAS` address/data-space saturation harness for EVD-RESOURCE (`RLIMIT_AS`/`DATA` → ENOMEM; Darwin unenforceable);
- Linux `platform.ACLRoundTrip`/`CopyACL` via `system.posix_acl_access` xattr (CapACL; CGO-free);
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
