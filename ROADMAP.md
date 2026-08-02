# Roadmap and entrance gates

Progress is evidence-gated, not date-gated. A milestone is complete only after
its acceptance criteria are met and independently approved.

## M0 — Assurance baseline

- criticality policy and claim boundaries;
- preliminary hazard analysis and threat model;
- foundational requirements and invariants;
- security architecture and authority map;
- daemon internal architecture (INT-ARCH-0001 component map);
- transaction, journal, protocol (incl. INT-PROTO-0001 replication contract),
  filesystem, and cryptographic specifications;
- Go profile, platform matrix, verification plan, and governance;
- automated referential-integrity and traceability checks.

Exit: no orphan requirement, hazard, threat, verification method, or evidence
record; formal models pass; two independent approvers accept every IC-1 item.

**Status:** baseline artifacts are complete; independent IC-1 approvers and
hosting branch-protection evidence remain open (see `docs/github-settings.md`).

## M1a — Local sync vertical slice (landed engineering)

- unidirectional local directory sync (`integris sync`);
- scan → plan → apply → verify with SHA-256 and staged rename;
- no network, daemon, auth, or deletions.

## M1b — Local journal + crash resume (landed engineering)

- IP-F-0001 journal under `destination/.integris/local.jrn`;
- per-op progress records; resume without replan from `last-plan.json`;
- torn-tail truncate; confirmation / cancellation records.

Exit: resume tests green; `docs/localsync.md` matches behaviour.

## M1c — Authenticated remote push (landed engineering)

- TCP push/serve using IP-P frames + provisional peer/archive auth + AEAD;
- shared root key (PSK); receiver stages then `localsync` apply (journaled);
- `integris push` / `integris serve`; Session `MaxAccept` default raised for
  data plane (TLA+ bound remains `MaxMessages=3` for model tests).

Exit: loopback round-trip + wrong-key refusal green; `docs/remotesync.md`.

## M1d — Chunked transfer + mid-file resume (landed engineering)

- application-level `FileBegin` / `FileAck` / `FileChunk` / `FileEnd`;
- default chunk 256 KiB (`-chunk-size`); removes ~1 MiB single-frame limit;
- durable partials under `destination/.integris/recv-partial/`;
- stage under `destination/.integris/recv-stage/` then journaled localsync apply;
- large-file and interrupt/resume tests green.

Exit: `docs/remotesync.md` matches behaviour.

## M2a — Privilege-separated receive (landed engineering)

- `integrisd serve` supervises `integrisd-net` + `integrisd-apply` (same binary
  re-exec) over authenticated local IPC;
- net holds TCP/PSK session; apply holds archive staging + localsync journal;
- push client unchanged (`integris push`); confinement via engineering adapters;
- e2e split-process push test green; `docs/daemon-m2a.md`.

Exit: loopback push through split roles green.

## M2b — Supervised restart + persistent serve (landed engineering)

- persistent net accept / apply session loops (multi-push without respawn);
- supervised net+apply pair restart with `-max-restarts` budget;
- ready address republished after restart; `Server.Status` health snapshot;
- multi-push and kill/restart e2e tests green; `docs/daemon-m2a.md`.

Exit: persistent push + restart-after-kill green.

## M2c — Auth role owns PSK handshake (landed engineering)

- `AuthNetApplyPlan`: net↔auth + net↔apply; push root key conferred to auth only;
- handshake via SCM_RIGHTS TCP FD + sealed session return to net;
- net holds sealed AEAD keys only (no PSK); apply data path unchanged;
- launcher `ExtraPeer` for dual IPC on net; e2e `TestM2cAuthPushServe` green.

Exit: push through auth+net+apply green; `docs/daemon-m2a.md`.

## M2d — Parser on the data plane (landed engineering)

- `AuthParserNetApplyPlan`: net↔auth, net↔parser, parser↔apply;
- `integrisd-parser` validates/decodes app messages (no PSK, no archive roots);
- apply peers parser only; net ExtraPeer → parser; parser ExtraPeer → apply;
- default for `integrisd serve`; e2e `TestM2dParserPushServe` green.

Exit: push through auth+parser+net+apply green; `docs/daemon-m2a.md`.

## M2e — Audit role redacted event sink (landed engineering)

- `AuthParserNetApplyAuditPlan`: M2d plus apply↔audit;
- `integrisd-audit` appends redacted observability events (no secrets/archives);
- apply ExtraPeer → audit; best-effort emit on commit (not IC-1 barrier);
- sink at `destination/.integris/audit.events`; default for `integrisd serve`;
- e2e `TestM2eAuditPushServe` green.

Exit: push through auth+parser+audit+net+apply green; `docs/daemon-m2a.md`.

## M2f — Journal role owns local.jrn (landed engineering)

- `AuthParserNetApplyJournalAuditPlan`: apply↔journal, journal↔audit;
- apply ExtraPeer is journal only (single ExtraPeer limit); audit relays via journal;
- `localsync.JournalSession` IPC backend; journal fail-closed, audit best-effort;
- default for `integrisd serve`; e2e `TestM2fJournalPushServe` green.

Exit: push through auth+parser+journal+audit+net+apply green; `docs/daemon-m2a.md`.

## M2g — Plan role on the data plane (landed engineering)

- `AuthParserNetPlanApplyJournalAuditPlan`: parser↔plan↔apply (+ journal/audit);
- `integrisd-plan` canonicalizes manifests and binds the file stream (no archive FS);
- ExtraPeer chain: parser→plan→apply→journal→audit; default for `integrisd serve`;
- e2e `TestM2gPlanPushServe` green.

Exit: push through auth+parser+plan+journal+audit+net+apply green; `docs/daemon-m2a.md`.

## M2h — Index role readonly destination scan (landed engineering)

- `AuthParserNetPlanIndexApplyJournalAuditPlan`: plan↔index↔apply (+ journal/audit);
- `integrisd-index` readonly `Scan(destination)` at commit; confers dest manifest;
- apply uses `localsync.Options.DestManifest` (skips dest Scan); default serve;
- e2e `TestM2hIndexPushServe` green; eight supervised receive roles + supervisor.

Exit: push through full eight-role receive chain green; `docs/daemon-m2a.md`.

## M2i — Per-peer PSK allow-list (landed engineering)

- named peer PSKs in `integrisd-auth` (`INTPEER1` keyring on root-key FD);
- unauthenticated peer prologue (`INTPID01`) selects admit key; MAC bound to peer id;
- `integrisd serve -peer-key ID=PATH` (repeatable) XOR `-key`/`-keyfile`;
- `integris push -peer ID` with matching keyfile; unknown/wrong key refuse closed;
- e2e `TestM2iPeerAllowListPushServe` green.

Exit: allow-list admit + deny without dest mutation; `docs/daemon-m2a.md`.

## M2j — Peer admit/deny audit events (landed engineering)

- when `Peers` keyring is set, auth ExtraPeer → audit (M2h plan variant);
- best-effort `auth.peer.admit` / `auth.peer.deny` with opaque peer digest only;
- shared-PSK topology unchanged (no auth ExtraPeer); not an IC-1 barrier;
- e2e asserts digests in `.integris/audit.events`.

Exit: keyring admit/deny visible in audit sink; `docs/daemon-m2a.md`.

## M2k — Strict / release-shaped launch (landed engineering)

- `launcher.ModeRelease` + `Request.ReleaseMode` (XOR `EngineeringMode`);
- `integrisd serve -strict-launch` / `ServeOptions.StrictLaunch`: full eight-role
  chain required; children get `INTEGRIS_LAUNCH_MODE=release`;
- confinement `APPLY-*` must be available (Unavailable/Skipped refuse);
- e2e `TestM2kStrictLaunchPushServe` + topology refuse test green.

Exit: strict launch push green on confined platforms; `docs/daemon-m2a.md`.
Next: broader authz / IC-1 evidence; full product release mode remains later.

## M2l — SCM-only key conferral (landed engineering)

- default `integrisd` / `Runtime` launch: ExtraFiles = primary IPC + key-channel
  child end (+ optional ExtraPeer IPC + allow-roots); keys via `SCM_RIGHTS` on
  `Handle.KeyChannel` (fd4 in child);
- `RootKey` / `ExtraMACKey` conferred on the same channel after the primary MAC;
- legacy `KeyViaExtraFiles` retained as opt-in;
- role-stub and `ClaimChild` receive keys from the key channel, not the IPC sock;
- e2e daemon + supervisor SCM path green; not an IC-1 / product release claim.

Exit: SCM default launch push green; `docs/daemon-m2a.md`.

## M2m — SCM dual-live StartPair (landed engineering)

- `StartPair` / `RestartPair` no longer require `KeyViaExtraFiles`;
- each dual-live child confers MAC keys on its own M2l key channel;
- legacy ExtraFiles dual-live path retained and tested;
- e2e `TestRuntimeRestartPairIPC` (SCM) + `TestRuntimeRestartPairExtraFiles`;
- not an IC-1 / product release claim.

Exit: dual-live SCM StartPair/RestartPair green; `docs/daemon-m2a.md`.

## M2n — In-place peer FD rebind (landed engineering)

- `Runtime.RestartOne`: kill failed dual-live end, `ReplacePair`, `StartChild`,
  `SendPeerFDFile` of the new peer IPC end on the survivor’s open `KeyChannel`;
- parent keeps `Handle.KeyChannel` after key bootstrap; stub
  `hold-initiate` / `hold-respond` + `Runtime.PairHold`;
- distinct `ipc.PeerFDMagic` (`IPER`) vs key conferral (`IKFD`);
- e2e `TestRuntimeRestartOneIPC` (survivor PID unchanged); not IC-1.

Exit: dual-live in-place rebind green; `docs/daemon-m2a.md`.

## M2o — Daemon RestartOne for M2a apply (landed engineering)

- `ClaimChild` keeps the key channel open for M2a net; `runNet` rebind loop
  accepts `RecvPeerFDFile` and swaps apply IPC + channel state;
- `supervise` calls `RestartOne` when apply exits under `DisableAuth` (net
  survives); other topologies keep full-fleet restart;
- e2e `TestM2oRestartOneApply` (net PID + listen addr unchanged; push after
  rebind); not an IC-1 claim.

Exit: M2a apply RestartOne green; `docs/daemon-m2a.md`.

## M2p — RestartOne for M2c ExtraPeer apply (landed engineering)

- M2c (`DisableParser`): net keeps key channel with ExtraPeer=apply; rebind loop
  rebuilds ExtraPeer channel (ExtraMACKey) and swaps data-plane socket;
- `tryRestartOne` covers M2a and M2c apply exits; auth PID unchanged on M2c;
- e2e `TestM2pRestartOneApplyExtraPeer`; not an IC-1 claim.

Exit: M2c ExtraPeer apply RestartOne green; `docs/daemon-m2a.md`.

## M2q — RestartOne for M2d parser ExtraPeer apply (landed engineering)

- M2d (`DisablePlan`+journal+audit): parser keeps key channel with
  ExtraPeer=apply; `ServeParserBridgeDyn` refreshes apply endpoint per request;
- `tryRestartOne` → `RestartOne(apply, parser, parser)`; net+auth PIDs unchanged;
- e2e `TestM2qRestartOneApplyParserExtraPeer`; not an IC-1 claim.

Exit: M2d parser ExtraPeer apply RestartOne green; `docs/daemon-m2a.md`.

## M2r — M2g plan ExtraPeer apply-subtree restart (landed engineering)

- M2g (`DisableIndex`): plan keeps key channel with ExtraPeer=apply;
  `ServePlanBridgeDyn` refreshes apply endpoint per forward;
- apply death (or journal/audit cascade) respawns apply+journal+audit and
  `SendPeerFDFile` into surviving plan; upstream PIDs unchanged;
- e2e `TestM2rRestartOneApplyPlanExtraPeer`; not an IC-1 claim.

Exit: M2g plan ExtraPeer apply-subtree restart green; `docs/daemon-m2a.md`.

## M2s — M2h index ExtraPeer apply-subtree restart (landed engineering)

- M2h full chain: index keeps key channel with ExtraPeer=apply;
  `ServeIndexBridgeDyn` refreshes apply endpoint per forward;
- shared `restartApplySubtree(bridge)` for M2r plan / M2s index;
- e2e `TestM2sRestartOneApplyIndexExtraPeer` (index+upstream PIDs unchanged);
  not an IC-1 claim.

Exit: M2h index ExtraPeer apply-subtree restart green; `docs/daemon-m2a.md`.

## M2t — M2d parser multi-edge restart (landed engineering)

- M2d: parser death kills/waits apply (primary EOF), ReplacePair net↔parser and
  parser↔apply, StartChild apply then parser, SendPeerFD into net ExtraPeer;
- net keeps key channel when ExtraPeer=parser; `runNet` rebind loop for parser;
- e2e `TestM2tRestartOneParserNetExtraPeer` (net+auth PIDs unchanged); not IC-1.

Exit: M2d parser→net ExtraPeer restart green; `docs/daemon-m2a.md`.

## M2u — M2g parser-downstream restart (landed engineering)

- M2g (`DisableIndex`): parser or plan death (or apply-subtree loss with parser
  already gone) respawns parser→plan→apply→journal→audit;
- ReplacePair net↔parser through journal↔audit; StartChild bottom-up; SendPeerFD
  into net ExtraPeer→parser; auth+net (listen) PIDs unchanged;
- e2e `TestM2uRestartOneParserDownM2g`; not an IC-1 claim.

Exit: M2g parser-downstream restart green; `docs/daemon-m2a.md`.

## M2v — M2h parser-downstream restart (landed engineering)

- M2h (full eight-role): parser/plan/index death (or apply-subtree loss with
  parser already gone) respawns parser→plan→index→apply→journal→audit;
- ReplacePair net↔parser through journal↔audit (incl. plan↔index↔apply);
  StartChild bottom-up; SendPeerFD into net ExtraPeer→parser; auth+net PIDs
  unchanged;
- e2e `TestM2vRestartOneParserDownM2h`; not an IC-1 claim.

Exit: M2h parser-downstream restart green; `docs/daemon-m2a.md`.

## M2w — M2c auth primary RestartOne (landed engineering)

- M2c: auth death respawns auth; rebinds net primary→auth via
  `PrimaryPeerFDMagic` / `SendPrimaryPeerFDFile` while ExtraPeer demux
  (`PeerFDMagic`) remains for apply;
- net KeyChannel demux (`RecvRebindFDFile` / `rebindNetDualLoop`); net+apply
  PIDs and listen addr unchanged;
- e2e `TestM2wRestartOneAuthNetPrimary`; not an IC-1 claim.

Exit: M2c auth primary rebind green; `docs/daemon-m2a.md`.

## M2x — M2d auth primary RestartOne (landed engineering)

- Same `restartAuthPrimary` path as M2w on M2d topology; net+parser+apply
  PIDs unchanged;
- e2e `TestM2xRestartOneAuthNetPrimaryM2d`; not an IC-1 claim.

Exit: M2d auth primary rebind green; `docs/daemon-m2a.md`.

## M2y — M2g auth primary RestartOne (landed engineering)

- Same path on M2g (`DisableIndex`); data-plane survivors keep PIDs;
- e2e `TestM2yRestartOneAuthNetPrimaryM2g`; not an IC-1 claim.

Exit: M2g auth primary rebind green; `docs/daemon-m2a.md`.

## M2z — M2h auth primary RestartOne (landed engineering)

- Same path on M2h full chain (shared PSK);
- e2e `TestM2zRestartOneAuthNetPrimaryM2h`; not an IC-1 claim.

Exit: M2h auth primary rebind green; `docs/daemon-m2a.md`.

## M3a — M2j auth ExtraPeer→audit RestartOne (landed engineering)

- M2h + peer keyring: auth death respawns auth; rebinds net primary→auth
  (`PrimaryPeerFDMagic`) and audit ExtraPeer→auth (`PeerFDMagic`);
- audit keeps KeyChannel when ExtraPeer=auth; `ServeAuditSinkExtraDyn` +
  `rebindPeerLoop`; audit+data-plane PIDs unchanged;
- e2e `TestM3aRestartOneAuthPeerAuditExtraPeer` (≥2 `auth.peer.admit`);
  not an IC-1 claim.

Exit: M2j auth→audit ExtraPeer restart green; `docs/daemon-m2a.md`.

## M3b — M2j audit→auth ExtraPeer RestartOne (landed engineering)

- M2h + peer keyring: apply/journal/audit subtree (and M2v parser-down) respawn
  rebinds surviving auth ExtraPeer→audit via `PeerFDMagic`;
- auth keeps KeyChannel when ExtraPeer=audit; `AuthAuditPeer.Side` snapshots;
- e2e `TestM3bRestartOneAuditAuthExtraPeer` (auth PID stable, ≥2 admits);
  not an IC-1 claim.

Exit: M2j audit→auth ExtraPeer restart green; `docs/daemon-m2a.md`.

## M3c — FreeBSD allow-root FD product claim (landed engineering)

- `ClaimChild` / `Confine` adopt `INTEGRIS_ALLOW_ROOT_FDS` and
  `LimitAllowRootFDs` before CapEnter (role-stub parity) for
  Apply/Index/Journal/Audit;
- shared `launcher.ClaimAllowRootFDs`; Journal/Audit FreeBSD `NEG-FS-WRITE`
  assertions mirror Apply/Index;
- not an IC-1 claim.

Exit: product Capsicum allow-root FD claim green; `docs/daemon-m2a.md`.

## M3d — Index destination ScanAt via openat (landed engineering)

- `localsync.ScanAt` walks a conferred directory FD with `openat`/`O_NOFOLLOW`;
- index bridge accepts optional `destDir`; `runIndex` passes `AllowRootFDs[0]`;
- unix parity `TestScanAtMatchesScan` / symlink refuse; FreeBSD
  `TestScanAtAfterCapEnter`; apply staging/journal openat still open at land;
  not an IC-1 claim.

Exit: index CapEnter-safe destination scan green; `docs/daemon-m2a.md`.

## M3e — Apply staging via openat (landed engineering)

- remotesync `localStore` stages `recv-partial` / `recv-stage` via openat on a
  conferred destination directory FD; `runApply` passes `AllowRootFDs[0]`;
- FreeBSD `LimitAllowRootFDs` RW rights include mkdirat/renameat/fsync/fchmod/
  ftruncate for staging; unix `TestOpenLocalStoreAtStaging` /
  FreeBSD `TestStageAtAfterCapEnter`;
- commit publish still ambient at land (M3g); not an IC-1 claim.

Exit: apply CapEnter-safe staging green; `docs/daemon-m2a.md`.

## M3f — Journal reopen via openat (landed engineering)

- `journal.OpenFileSegmentAt` + `localsync.OpenFileJournalAt` reopen
  `.integris/local.jrn` via openat on a conferred destination FD;
- `runJournal` passes `AllowRootFDs[0]` into `ServeJournalIPC`; prefix bytes
  read from the open segment (no ambient re-open);
- unix `TestOpenFileJournalAtReopen` / FreeBSD `TestJournalAtAfterCapEnter`;
  not an IC-1 claim.

Exit: journal CapEnter-safe reopen green; `docs/daemon-m2a.md`.

## M3g — Apply publish via openat (landed engineering)

- `localsync.ApplyAt` / `Sync` with `SourceFD`+`DestFD`: ScanAt stage, ApplyAt
  mkdir/copy/replace, plan snapshot openat, resolveRoots via fstat;
- `localStore.commit` passes stage/dest FDs; `resetStageAt` clears via unlinkat;
- unix `TestApplyAtMatchesApply` / `TestSyncAtJournaled`; FreeBSD
  `TestApplyAtAfterCapEnter`; not an IC-1 claim.

Exit: CapEnter-safe staged publish green; `docs/daemon-m2a.md`.

## M3h — Audit sink openat bootstrap (landed engineering)

- `remotesync.OpenAuditSinkAt` creates/opens `.integris/audit.events` via openat
  on a conferred destination FD before CapEnter; sink FD held across Confine;
- Audit allow-root stays readonly (archive create still denied); `runAudit`
  prefers `AllowRootFDs[0]`;
- unix `TestOpenAuditSinkAt` / FreeBSD `TestAuditSinkAtAfterCapEnter`;
  not an IC-1 claim.

Exit: audit CapEnter-held sink green; `docs/daemon-m2a.md`.

## M3i — CapEnter receive openat chain proof (landed engineering)

- single-session proof: stage → ScanAt dest snapshot → journaled `Sync` publish
  via FDs → held audit sink write;
- unix `TestReceiveOpenatChain`; FreeBSD `TestReceiveOpenatChainAfterCapEnter`
  (ambient path fails; openat chain succeeds under CapEnter);
- not a supervised multi-process CapEnter push; not an IC-1 claim.

Exit: CapEnter openat receive chain green; `docs/daemon-m2a.md`.

## M3j — RestartOne exit-channel drain hardening (landed engineering)

- `flushExitPending` after selective-restart wait loops and before re-arming
  watchers so cascade sibling exits do not burn `MaxRestarts`;
- `armWatcher` signals `exitCh` only for the current handle (superseded
  RestartOne replacements stay silent);
- `TestFlushExitPending`; RestartOne stress on M3b/M2z paths; not an IC-1 claim.

Exit: stale buffered exits no longer trigger spurious RestartOne; `docs/daemon-m2a.md`.

## M3k — FreeBSD CapEnter stub probe NEG-CAP-MODE (landed engineering)

- `confine.NegativeCapMode` via `cap_getmode(2)`; wired into
  `NegativeEngineeringOpts` / stub ack as `|NEG-CAP-MODE:`;
- FreeBSD supervised role-stub asserts `|NEG-CAP-MODE:available` after CapEnter;
  other OS `|NEG-CAP-MODE:skipped`;
- unit `TestNegativeCapModeAfterCapEnter`; not an IC-1 claim.

Exit: supervised CapEnter mode probe green; `docs/daemon-m2a.md`.

## M3l — Journal ambient bootstrap via openat (landed engineering)

- `remotesync.BootstrapJournalAt` creates `.integris/local.jrn` via openat on a
  conferred destination FD before CapEnter (M3h audit sink parity);
- `runJournal` prefers `AllowRootFDs[0]`; ambient path remains when no FD;
- unix `TestBootstrapJournalAt` / FreeBSD `TestJournalBootstrapAtAfterCapEnter`;
  not an IC-1 claim.

Exit: journal CapEnter bootstrap green; `docs/daemon-m2a.md`.

## M3m — Product CapEnter self-check fail-closed (landed engineering)

- release-mode `ChildEnv.Confine` calls `confine.RequireCapModeAvailable`
  after APPLY-* (FreeBSD `cap_getmode` must report capability mode);
- non-FreeBSD CapMode check is skipped; engineering launch stays best-effort;
- unit `TestRequireCapModeFinding` / FreeBSD
  `TestRequireCapModeAvailableAfterCapEnter`; not an IC-1 claim.

Exit: product CapEnter post-condition green; `docs/daemon-m2a.md`.

## M3n — Product allow-root Capsicum rights fail-closed (landed engineering)

- release-mode `ChildEnv.Confine` checks `LimitAllowRootFDs` via
  `RequireAllowRootLimitFinding` (`APPLY-CAP-ALLOW-ROOTS`);
- Available or Skipped succeed; Unavailable refuses; engineering stays
  best-effort; non-FreeBSD Skipped OK;
- unit `TestRequireAllowRootLimitFinding` / FreeBSD
  `TestRequireAllowRootLimitAfterLimit`; not an IC-1 claim.

Exit: product allow-root rights-limit post-condition green; `docs/daemon-m2a.md`.

## M3o — Product conferred Capsicum rights fail-closed (landed engineering)

- `ClaimChild` stores `LimitConferredFDs` on `ChildEnv.ConferredRights`;
- release-mode `Confine` checks via `RequireConferredLimitFinding`
  (`APPLY-CAP-RIGHTS`); Available or Skipped succeed; Unavailable refuses;
- unit `TestRequireConferredLimitFinding` / FreeBSD
  `TestRequireConferredLimitAfterLimit`; not an IC-1 claim.

Exit: product conferred IPC/key rights-limit post-condition green;
`docs/daemon-m2a.md`.

## M3p — FreeBSD supervised CapEnter push first cut (landed engineering)

- FreeBSD `TestM3pStrictLaunchCapEnterPushServe`: StrictLaunch Once product
  push under CapEnter-capable children (M3m–M3o); journal/audit/plan present;
- archive-role stub AllowRoots acks assert `|NEG-CAP-MODE:available` on
  FreeBSD (apply/index/journal/audit + restart); other OS skipped;
- not a full ambient-denial / RestartOne CapEnter campaign; not an IC-1 claim.

Exit: supervised CapEnter push first cut green; `docs/daemon-m2a.md`.

## M3q — Product CapEnter ambient FS-read deny fail-closed (landed engineering)

- release-mode `ChildEnv.Confine` calls `RequireAmbientFSReadDenied`
  (`NEG-FS-READ` DeniedExpected or Skipped);
- FreeBSD AllowRoots stub acks assert `|NEG-FS-READ:denied_as_expected`
  beside openat `|NEG-FS-PATH:available`;
- unit `TestRequireAmbientFSReadFinding` / FreeBSD
  `TestRequireAmbientFSReadDeniedAfterCapEnter`; not an IC-1 claim.

Exit: product ambient FS-read deny post-condition green; `docs/daemon-m2a.md`.

## M3r — FreeBSD StrictLaunch CapEnter RestartOne first cut (landed engineering)

- FreeBSD `TestM3rStrictLaunchCapEnterRestartOneApply`: StrictLaunch persistent
  serve under CapEnter; kill apply after first push; net PID + listen addr
  survive; apply+journal+audit subtree respawns; second push succeeds;
- replacement children keep M3m–M3q fail-closed confine; not a full ambient
  socket / NEG-ROLE-NET CapEnter campaign; not an IC-1 claim.

Exit: supervised CapEnter RestartOne first cut green; `docs/daemon-m2a.md`.

## M3s — FreeBSD ambient AF_INET residual documented (landed engineering)

- CapEnter does not deny `AF_INET` `socket()`/`connect()` (`NEG-ROLE-NET`
  UnexpectedAllow after apply); product children keep allow-root
  `CapRightsLimit` before CapEnter;
- jail `ip4=disable` was evaluated and rejected for product use: it conflicts
  with conferred archive FD rights-limit / StrictLaunch receive;
- FreeBSD `TestM3sCapEnterLeavesAmbientAFINET` + `PROBE-JAIL-NOIP` Unavailable
  residual; `RequireAmbientRoleNetDenied` no-ops on FreeBSD (wired for
  Linux/Darwin/OpenBSD in M4d); not an IC-1 claim.

Exit: FreeBSD ambient-socket residual explicit; `docs/daemon-m2a.md`.

## M3t — FreeBSD sealed MAC key FD (landed engineering)

- FreeBSD `CreateKeyFD` uses `shm_open2(SHM_ANON)` + `F_ADD_SEALS`
  (`F_SEAL_WRITE|SHRINK|GROW|SEAL`), same transport label as Linux
  (`memfd-sealed`); pure Go / `CGO_ENABLED=0`;
- `DISC-KEY-FD` Available on FreeBSD; Darwin/OpenBSD remain anon-unlinked
  residual; not an IC-1 claim.

Exit: FreeBSD sealed key FD green; `docs/daemon-m2a.md`.

## M3u — FreeBSD StrictLaunch CapEnter parser-down RestartOne (landed engineering)

- FreeBSD `TestM3uStrictLaunchCapEnterRestartOneParserDown`: StrictLaunch
  persistent serve under CapEnter; kill parser after first push; net+auth PIDs
  and listen addr survive; parser→plan→index→apply→journal→audit respawn with
  M3m–M3q fail-closed confine; second push succeeds (M2v path under CapEnter);
- not an IC-1 claim.

Exit: supervised CapEnter parser-down RestartOne green; `docs/daemon-m2a.md`.

## M3v — FreeBSD StrictLaunch CapEnter auth-primary RestartOne (landed engineering)

- FreeBSD `TestM3vStrictLaunchCapEnterRestartOneAuthPrimary`: StrictLaunch
  persistent serve under CapEnter; kill auth after first push; net and full
  data plane PIDs + listen addr survive; auth respawns with primary peer
  rebind under M3m–M3q fail-closed confine; second push succeeds (M2z path
  under CapEnter);
- not an IC-1 claim.

Exit: supervised CapEnter auth-primary RestartOne green; `docs/daemon-m2a.md`.

## M3w — FreeBSD StrictLaunch CapEnter M2j auth ExtraPeer RestartOne (landed engineering)

- FreeBSD `TestM3wStrictLaunchCapEnterRestartOneAuthPeerExtraPeer`: StrictLaunch
  persistent serve under CapEnter with peer keyring; kill auth after first peer
  push; net + full data plane + listen survive; auth respawns with primary and
  audit ExtraPeer rebind under M3m–M3q fail-closed confine; second peer push
  yields ≥2 `auth.peer.admit` (M3a path under CapEnter);
- not an IC-1 claim.

Exit: supervised CapEnter peer-auth ExtraPeer RestartOne green; `docs/daemon-m2a.md`.

## M3x — FreeBSD StrictLaunch CapEnter M2j audit ExtraPeer RestartOne (landed engineering)

- FreeBSD `TestM3xStrictLaunchCapEnterRestartOneAuditAuthExtraPeer`: StrictLaunch
  persistent serve under CapEnter with peer keyring; kill audit after first peer
  push; auth+net+parser+plan+index + listen survive; apply+journal+audit
  respawn with auth ExtraPeer→audit rebind under M3m–M3q fail-closed confine;
  second peer push yields ≥2 `auth.peer.admit` (M3b path under CapEnter);
- not an IC-1 claim.

Exit: supervised CapEnter audit ExtraPeer RestartOne green; `docs/daemon-m2a.md`.

## M3y — FreeBSD StrictLaunch CapEnter M2j peer-key push (landed engineering)

- FreeBSD `TestM3yStrictLaunchCapEnterPeerPushServe`: StrictLaunch Once product
  children with peer keyring under CapEnter (M3m–M3q fail-closed); peer push
  succeeds with journal/audit/plan and ≥1 `auth.peer.admit` (M3p + M2j);
- not an IC-1 claim.

Exit: supervised CapEnter peer-key push green; `docs/daemon-m2a.md`.

## M3z — FreeBSD StrictLaunch CapEnter M2j apply RestartOne (landed engineering)

- FreeBSD `TestM3zStrictLaunchCapEnterRestartOneApplyPeer`: StrictLaunch
  persistent serve under CapEnter with peer keyring; kill apply after first peer
  push; net+auth+index + listen survive; apply+journal+audit respawn under
  M3m–M3q fail-closed confine; second peer push yields ≥2 `auth.peer.admit`
  (M3r path under M2j);
- not an IC-1 claim.

Exit: supervised CapEnter peer-apply RestartOne green; `docs/daemon-m2a.md`.

## M4a — FreeBSD StrictLaunch CapEnter M2j parser-down RestartOne (landed engineering)

- FreeBSD `TestM4aStrictLaunchCapEnterRestartOneParserDownPeer`: StrictLaunch
  persistent serve under CapEnter with peer keyring; kill parser after first peer
  push; net+auth + listen survive; parser→plan→index→apply→journal→audit
  respawn under M3m–M3q fail-closed confine; second peer push yields ≥2
  `auth.peer.admit` (M3u path under M2j);
- not an IC-1 claim.

Exit: supervised CapEnter peer parser-down RestartOne green; `docs/daemon-m2a.md`.

## M4b — FreeBSD StrictLaunch CapEnter M2j peer deny/admit (landed engineering)

- FreeBSD `TestM4bStrictLaunchCapEnterPeerDenyAdmit`: StrictLaunch persistent
  serve under CapEnter with peer keyring; unknown peer and wrong-key pushes are
  rejected without destination mutation; valid peer push succeeds with
  journal/audit/plan and both `auth.peer.deny` + `auth.peer.admit` (M2i under
  CapEnter StrictLaunch / M3m–M3q fail-closed);
- not an IC-1 claim.

Exit: supervised CapEnter peer deny/admit green; `docs/daemon-m2a.md`.

## M4c — Darwin/OpenBSD anon key FD residual documented (landed engineering)

- Darwin/OpenBSD `CreateKeyFD` remains anon-unlinked O_RDONLY
  (`KeyTransportAnonFile`); no `memfd_create` / `F_ADD_SEALS`;
- `DISC-KEY-FD` Unavailable on Darwin/OpenBSD with residual detail;
  `TestM4cCreateKeyFDAnonUnlinkedResidual` asserts transport + O_RDONLY write
  deny; Linux/FreeBSD sealed path unchanged; not an IC-1 claim.

Exit: Darwin/OpenBSD key FD residual explicit; `docs/daemon-m2a.md`.

## M4d — Release ambient ROLE-NET deny (non-FreeBSD) (landed engineering)

- release-mode `ChildEnv.Confine` calls `RequireAmbientRoleNetDenied`
  (`NEG-ROLE-NET` DeniedExpected or Skipped) on Linux/Darwin/OpenBSD after
  apply (seccomp/Seatbelt/pledge already deny ambient AF_INET for non-net
  roles);
- FreeBSD remains a no-op (M3s residual: CapEnter leaves sockets; jail
  ip-disable still conflicts with allow-root CapRightsLimit);
- unit `TestRequireAmbientRoleNetFinding` / Darwin Seatbelt after apply /
  FreeBSD CapEnter residual noop / CapNetwork role Skipped; Linux/OpenBSD
  covered by role-stub `|NEG-ROLE-NET:denied_as_expected` (ApplyEngineering
  mutates the process and breaks coverage meta under Landlock); not an IC-1 claim.

Exit: non-FreeBSD release ambient ROLE-NET deny post-condition green;
`docs/daemon-m2a.md`.

## M4e — Darwin StrictLaunch Seatbelt push first cut (landed engineering)

- Darwin `TestM4eStrictLaunchSeatbeltPushServe`: StrictLaunch Once product
  children under Seatbelt `sandbox_init` (cgo) complete a push with
  journal/audit/plan (M2k + M3q/M4d fail-closed ambient FS-read + ROLE-NET);
- FreeBSD CapEnter push first cut remains M3p; not an IC-1 claim.

Exit: supervised Darwin Seatbelt StrictLaunch push first cut green;
`docs/daemon-m2a.md`.

## M4f — Darwin StrictLaunch Seatbelt RestartOne apply (landed engineering)

- Darwin `TestM4fStrictLaunchSeatbeltRestartOneApply`: StrictLaunch persistent
  serve under Seatbelt; kill apply after first push; net PID + listen addr
  survive; apply+journal+audit subtree respawns with M3q/M4d fail-closed
  confine; second push succeeds (M3r Darwin parity);
- not an IC-1 claim.

Exit: supervised Darwin Seatbelt RestartOne first cut green;
`docs/daemon-m2a.md`.

## M4g — Darwin StrictLaunch Seatbelt parser-down RestartOne (landed engineering)

- Darwin `TestM4gStrictLaunchSeatbeltRestartOneParserDown`: StrictLaunch
  persistent serve under Seatbelt; kill parser after first push; net+auth +
  listen survive; parser→plan→index→apply→journal→audit respawn with M3q/M4d
  fail-closed confine; second push succeeds (M3u Darwin parity);
- not an IC-1 claim.

Exit: supervised Darwin Seatbelt parser-down RestartOne green;
`docs/daemon-m2a.md`.

## M4h — Darwin StrictLaunch Seatbelt auth-primary RestartOne (landed engineering)

- Darwin `TestM4hStrictLaunchSeatbeltRestartOneAuthPrimary`: StrictLaunch
  persistent serve under Seatbelt; kill auth after first push; net + full data
  plane + listen survive; auth respawns with primary peer rebind under M3q/M4d
  fail-closed confine; second push succeeds (M3v Darwin parity);
- not an IC-1 claim.

Exit: supervised Darwin Seatbelt auth-primary RestartOne green;
`docs/daemon-m2a.md`.

## M4i — Darwin StrictLaunch Seatbelt auth ExtraPeer RestartOne (landed engineering)

- Darwin `TestM4iStrictLaunchSeatbeltRestartOneAuthPeerExtraPeer`: peer
  keyring StrictLaunch under Seatbelt; kill auth after first push; net + data
  plane + listen survive; auth respawns with primary + audit ExtraPeer rebind;
  ≥2 `auth.peer.admit` (M3w Darwin parity);
- not an IC-1 claim.

Exit: supervised Darwin Seatbelt auth ExtraPeer RestartOne green;
`docs/daemon-m2a.md`.

## M4j — Darwin StrictLaunch Seatbelt audit ExtraPeer RestartOne (landed engineering)

- Darwin `TestM4jStrictLaunchSeatbeltRestartOneAuditAuthExtraPeer`: peer
  keyring StrictLaunch under Seatbelt; kill audit after first push; auth+net+
  parser+plan+index + listen survive; apply+journal+audit respawn with auth
  ExtraPeer→audit rebind; ≥2 `auth.peer.admit` (M3x Darwin parity);
- not an IC-1 claim.

Exit: supervised Darwin Seatbelt audit ExtraPeer RestartOne green;
`docs/daemon-m2a.md`.

## M1 — Executable reference kernels (in progress)

- canonical codec with resource limits;
- safe relative-name grammar;
- journal reader/writer and independent verifier;
- deterministic planner;
- transaction recovery kernel;
- conformance tests derived from the models.

Entrance: M0 exit criteria, an accepted IP for each kernel, and an assigned
technical and security reviewer. Exit: complete IC-1/IC-2 evidence, continuous
fuzzing, fault injection, and cross-platform tests.

**Status:** draft IPs IP-S-0001, IP-F-0001, IP-S-0002, IP-S-0003, IP-P-0001 and
reference packages under `internal/` exist (path, codec, journal, plan,
recovery, config, resource, deletion, fsmodel, authority, observability, ipc,
session, protocol; M2 prelude: supervisor grant planning). Produced evidence so
far: EVD-JOURNAL-001, EVD-PLAN-001, EVD-RECOVERY-001, EVD-CONFIG-001,
EVD-RESOURCE-001. IC-1 path/arch/delete/fs/txn/proto campaigns remain planned
pending independent review, crypto suite, and platform probes.

## M2 — Privilege-separated prototype

- supervisor and minimum-authority subprocesses;
- authenticated, bounded local IPC;
- native confinement adapters for all declared platforms;
- destructive-operation quarantine and recovery harness.

**Status (prelude):** engineering children apply Landlock+seccomp (Linux),
pledge (OpenBSD), Capsicum+cap_rights_limit (FreeBSD), or Seatbelt sandbox_init
(Darwin, cgo) with role-parameterized ambient network denial; stub reports
NEG-FS/FS-READ/FS-PATH/FS-WRITE/EXEC/PTRACE/ROLE-NET and role-semantic conferral NEG-*
(including complete inventory MustNot conferral probes for all nine roles; CapNetwork via NEG-ROLE-NET + conferral); Runtime
orchestrates spawn (AllowRoots→stub), RestartChild, RestartPair (M2m), RestartOne peer-FD rebind (M2n);
Apply/Index/Journal/Audit path allow-roots (Index/Audit readonly write denial probed);
hostile IPC refuse matrix; Apply/Index path allow-roots (Index readonly write denial probed);
orchestrates spawn (AllowRoots→stub), RestartChild (retains AllowRoots), RestartPair (M2m), RestartOne (M2n);
Apply/Index path allow-roots (Index readonly write denial probed);
Apply/Index path allow-roots (Index readonly write denial probed; FreeBSD via
conferred directory FDs + Capsicum rights);
journal `CrashSegment` exercises J-APPEND-PRE/MID/POST + J-META-POST on FileSegment
with Recover round-trip; recovery-side P-* PersistIO FailAt covers STAGE/PUBLISH/CONFIRM
on FilePersist; apply-side `FilePublisher` covers stage→rename→dirsync FailAt with
Observation→Recover; OS SIGKILL at J-* and P-STAGE/P-PUBLISH labels via crash-stub
(`CrashSegment.KillAt` / `FilePublisher.KillAt`); Darwin `F_FULLFSYNC` via
`platform.SyncFile` and `clonefile`/`FICLONE` via `platform.CloneFile`→`PublishFrom`
(with sparse `SEEK_DATA`/`SEEK_HOLE` + `CopyXattr`+`CopyBSDFlags`+`CopyACL`+
`CopyResourceFork`+`CopyTimes` incl. Darwin birthtime on degraded byte-copy);
CapCOW/CapXattr/CapBSDFlags/CapSparse/CapResourceFork/CapTimes/CapACL/CapUnicode
probed in `fsmodel.ProbeScratch`;
Darwin abrupt-detach SyncFile-survive harness landed; unflushed-loss
differential host-dependent; `platform.SendFile` sendfile→socket harness on
Darwin/Linux/FreeBSD, OpenBSD unavailable);
differential host-dependent; `platform.VNodeWatch` kqueue VNODE notify
harness on Darwin/FreeBSD/OpenBSD);
sealed MAC key FD (Linux/FreeBSD sealed memfd-equivalent; Darwin/OpenBSD
anon-unlinked residual) with SCM_RIGHTS default (legacy ExtraFiles fd4 opt-in); provisional session AEAD with suite
negotiation, HMAC peer-auth (`i2r`+`r2i`), and transcript-bound traffic keys
(IP-C-0002). Finished handshake/PQ and IC-1 review remain open.

Exit: red-team review, crash testing at every persistence point, platform
evidence, and no open IC-1 defects.

## M3 — Protocol interoperability preview

- mutually authenticated sessions;
- downgrade-resistant negotiation;
- resumable bounded content transfer;
- hostile-peer and multi-version test suites.

**Status (prelude):** suite allow-list + TypeData AEAD over `protocol.Driver`
with transcript-bound keys; `TypeNegotiateOffer` / `TypeNegotiateAccept` carry
versions and suite IDs on the wire (offer allow-list + accept confirm);
mutual provisional HMAC peer-auth (`i2r`+`r2i`) and archive-auth proofs exist;
consolidated hostile-peer Driver refuse matrix and multi-version negotiate
happy-path suite (`hostile_peer_test.go`, `multi_version_test.go`); TypeData
chunk envelope (`offset||length||data`) with optional contiguous resume
tracking (`TrackDataChunks` / gap+replay refuse); Noise/TLS handshake and PQ
remain open.

Exit: independent protocol/cryptographic review and published test vectors.

## M4 — Release candidate

- reproducible artifacts, SBOMs, signatures, and SLSA provenance;
- operator, recovery, upgrade, rollback, revocation, and retirement procedures;
- an independent rebuild and all release evidence.

No stable release exists until every criterion in `docs/release-policy.md` is met.
