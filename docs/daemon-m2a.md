# Privilege-separated receive (M2a–M4y engineering increments)

Status: **Implemented engineering preview (not the product daemon)**  
Package: `internal/daemon`  
Command: `integrisd serve`

## Purpose

Cross OS process boundaries on the receive path (eight supervised children;
supervisor is the parent process):

```text
integris push [-peer ID]
    |  INTPRO01 + PSK (optional INTPID01 peer prologue)
    v
integrisd-net      TCP accept; AEAD data plane; no push root key
    |  SCM_RIGHTS + INTIPC (handshake)
    v
integrisd-auth     PSK or INTPEER1 keyring + AcceptHandshake → sealed session
    |  INTIPC01 (M2j: admit/deny when -peer-key)
    v
integrisd-audit    redacted event sink (also journal→audit)
    |
integrisd-net      sealed session
    |  INTIPC01
    v
integrisd-parser   validate/decode app messages
    |  INTIPC01
    v
integrisd-plan     canonicalize manifest; bind file stream to authorized plan
    |  INTIPC01
    v
integrisd-index    readonly Scan(destination) at commit; relay to apply
    |  INTIPC01 (+ dest manifest)
    v
integrisd-apply    staging + archive publish (uses index dest snapshot)
    |  INTIPC01
    v
integrisd-journal  owns local.jrn
    |  INTIPC01
    v
integrisd-audit    redacted event sink
```

ExtraPeer chain (one extra peer per child):

| Role | Primary | ExtraPeer |
|---|---|---|
| net | auth | parser |
| auth | net | audit (only with `-peer-key` / `Peers`) |
| parser | net | plan |
| plan | parser | index |
| index | plan | apply |
| apply | index | journal |
| journal | apply | audit |
| audit | journal | auth (only with peer keyring) |

## Supported

- **M2a–M2g:** as previously documented (`DisableIndex` restores M2g)
- **M2h (default):** `integrisd-index` between plan and apply; requires plan+journal+audit
- **M2i:** per-peer PSK allow-list in `integrisd-auth` (`-peer-key ID=PATH`, push `-peer ID`);
  unauthenticated peer prologue selects the PSK; unknown ID / wrong key refuse closed
- **M2j:** with a peer keyring, auth ExtraPeer→audit emits best-effort
  `auth.peer.admit` / `auth.peer.deny` (opaque peer digest only)
- **M2k:** `-strict-launch` / `StrictLaunch` — full eight-role chain; children
  launch with `INTEGRIS_LAUNCH_MODE=release`; confinement APPLY-* fail-closed
  (M3m–M4y CapMode, Capsicum rights-limit, ambient FS-read deny, ambient
  ROLE-NET deny on non-FreeBSD, CapEnter/Seatbelt/Landlock/pledge StrictLaunch
  push, RestartOne, and peer deny/admit; FreeBSD ambient AF_INET residual
  documented on FreeBSD)
- **M2l:** default key conferral is SCM-only — ExtraFiles carries IPC sockets plus
  a dedicated key-channel socketpair end (fd4); MAC/root/extra keys arrive via
  `SCM_RIGHTS` on that channel (`Handle.KeyChannel`). Legacy
  `Runtime.KeyViaExtraFiles` remains opt-in
- **M2m:** `StartPair` / `RestartPair` dual-live edges work on the default SCM
  key-channel path (each child has its own `KeyChannel`); ExtraFiles dual-live
  remains supported
- **M2n:** `RestartOne` rebinds a replacement peer IPC FD into a surviving
  dual-live child via `SCM_RIGHTS` (`PeerFDMagic` / `SendPeerFDFile`) on the
  open key channel; survivor PID unchanged; engineering stub hold modes
  (`hold-initiate` / `hold-respond`)
- **M2o:** daemon wiring of `RestartOne` for M2a (`DisableAuth`) apply exits —
  surviving `integrisd-net` keeps listen socket + PID; peer IPC rebind via key
  channel
- **M2p:** `RestartOne` for M2c (`DisableParser`) apply exits — rebinds net’s
  ExtraPeer→apply socket while auth + listen survive
- **M2q:** `RestartOne` for M2d apply exits — rebinds parser’s ExtraPeer→apply
  socket while parser + net + auth survive
- **M2r:** M2g (`DisableIndex`) apply death — rebinds plan ExtraPeer→apply while
  plan/parser/net/auth survive; apply+journal+audit subtree respawns (journal
  EOF on apply death)
- **M2s:** M2h (full eight-role) apply death — rebinds index ExtraPeer→apply while
  index+plan+parser+net+auth survive; same apply+journal+audit subtree respawn
- **M2t:** M2d parser death — respawns parser+apply and rebinds net ExtraPeer→parser
  while auth+net (listen) survive
- **M2u:** M2g (`DisableIndex`) parser/plan death — respawns
  parser→plan→apply→journal→audit and rebinds net ExtraPeer→parser while
  auth+net (listen) survive
- **M2v:** M2h (full eight-role) parser/plan/index death — respawns
  parser→plan→index→apply→journal→audit and rebinds net ExtraPeer→parser while
  auth+net (listen) survive
- **M2w:** M2c auth death — respawns auth and rebinds net primary→auth via
  `PrimaryPeerFDMagic` demux on the key channel while net+apply+listen survive
- **M2x/M2y/M2z:** same auth-primary RestartOne on M2d / M2g / M2h (shared PSK);
  data-plane survivors keep PIDs
- **M3a:** M2h + peer keyring — auth death also rebinds audit ExtraPeer→auth
  while audit+data-plane PIDs survive (`ServeAuditSinkExtraDyn`)
- **M3b:** M2h + peer keyring — apply/audit subtree (or parser-down) respawn
  rebinds surviving auth ExtraPeer→audit while auth PID survives
- **M3c:** FreeBSD product children claim conferred allow-root directory FDs
  (`INTEGRIS_ALLOW_ROOT_FDS`) and `LimitAllowRootFDs` before CapEnter
  (Apply/Index/Journal/Audit); stub parity
- **M3d:** index destination scan via `localsync.ScanAt` / `openat` on the
  conferred allow-root FD (CapEnter-safe); path `Scan` remains for non-FD callers
- **M3e:** apply staging (`recv-stage` / `recv-partial`) via openat on the
  conferred allow-root FD; ambient path staging remains when no FD is conferred
- **M3f:** journal reopen of `.integris/local.jrn` via openat on the conferred
  allow-root FD; ambient path open remains when no FD is conferred
- **M3g:** apply publish via `localsync.ApplyAt` / `Sync` with conferred
  stage+dest FDs (ScanAt, plan snapshot openat, unlinkat stage wipe); ambient
  Sync remains when no FDs are conferred
- **M3h:** audit sink `.integris/audit.events` opened via openat on the conferred
  allow-root FD before CapEnter; held sink FD used after Confine; Audit archive
  allow-root stays readonly
- **M3i:** CapEnter receive openat chain proof (stage → ScanAt → journaled
  publish → audit sink) under one capability-mode session; not a supervised
  multi-process CapEnter push
- **M3j:** RestartOne exit-channel drain — flush buffered cascade exits before
  re-arming watchers; superseded handles do not signal `exitCh`
- **M3k:** FreeBSD CapEnter stub probe `|NEG-CAP-MODE:` via `cap_getmode(2)`;
  supervised role-stub asserts capability mode after apply
- **M3l:** journal bootstrap of `.integris/local.jrn` via openat on the conferred
  allow-root FD before CapEnter (M3h audit sink parity); reopen remains M3f
- **M3m:** product children in `INTEGRIS_LAUNCH_MODE=release` fail closed unless
  FreeBSD capability mode is confirmed (`RequireCapModeAvailable` /
  `cap_getmode`); non-FreeBSD CapMode check is skipped; engineering launch
  remains best-effort
- **M3n:** release-mode `Confine` fails closed unless FreeBSD allow-root
  `cap_rights_limit` succeeded (`RequireAllowRootLimitFinding` /
  `APPLY-CAP-ALLOW-ROOTS`); Skipped when no FDs / non-FreeBSD; engineering
  launch remains best-effort
- **M3o:** release-mode `Confine` fails closed unless FreeBSD conferred IPC/key
  `cap_rights_limit` succeeded (`RequireConferredLimitFinding` /
  `APPLY-CAP-RIGHTS` from `ClaimChild`); Skipped on non-FreeBSD; engineering
  launch remains best-effort
- **M3p:** FreeBSD supervised CapEnter push first cut — StrictLaunch Once
  product push under M3m–M3o fail-closed CapMode/rights; archive-role stub
  AllowRoots acks assert `|NEG-CAP-MODE:available` (apply/index/journal/audit)
- **M3q:** release-mode `Confine` fails closed unless ambient path open is
  denied (`RequireAmbientFSReadDenied` / `NEG-FS-READ`); FreeBSD AllowRoots
  stubs also assert `|NEG-FS-READ:denied_as_expected` beside openat path allow
- **M3r:** FreeBSD StrictLaunch CapEnter RestartOne first cut — persistent
  serve under CapEnter; kill apply; net PID + listen addr survive;
  apply+journal+audit subtree respawns with M3m–M3q fail-closed confine;
  second push succeeds
- **M3s:** FreeBSD ambient AF_INET residual — CapEnter does not deny sockets
  (`NEG-ROLE-NET` UnexpectedAllow); jail ip-disable evaluated and rejected for
  product children (conflicts with allow-root `CapRightsLimit`); residual probe
  + CapEnter test; `RequireAmbientRoleNetDenied` no-ops on FreeBSD; wired on
  Linux/Darwin/OpenBSD in M4d; `RequireAmbientRoleNetFinding` is the probe core
- **M3t:** FreeBSD sealed MAC key FD — `CreateKeyFD` via `shm_open2(SHM_ANON)`
  + `F_ADD_SEALS` (`memfd-sealed`); `DISC-KEY-FD` Available; Darwin/OpenBSD
  remain anon-unlinked residual
- **M3u:** FreeBSD StrictLaunch CapEnter parser-down RestartOne — kill parser;
  net+auth + listen survive; parser→plan→index→apply→journal→audit respawn
  under M3m–M3q fail-closed confine; second push succeeds (M2v under CapEnter)
- **M3v:** FreeBSD StrictLaunch CapEnter auth-primary RestartOne — kill auth;
  net + full data plane + listen survive; auth respawns with primary peer
  rebind under M3m–M3q fail-closed confine; second push succeeds (M2z under
  CapEnter)
- **M3w:** FreeBSD StrictLaunch CapEnter M2j auth ExtraPeer RestartOne — peer
  keyring; kill auth; data plane + listen survive; auth respawns with primary
  + audit ExtraPeer rebind; ≥2 `auth.peer.admit` (M3a under CapEnter)
- **M3x:** FreeBSD StrictLaunch CapEnter M2j audit ExtraPeer RestartOne — peer
  keyring; kill audit; auth+upstream + listen survive; apply+journal+audit
  respawn with auth ExtraPeer→audit rebind; ≥2 `auth.peer.admit` (M3b under
  CapEnter)
- **M3y:** FreeBSD StrictLaunch CapEnter M2j peer-key push — StrictLaunch Once
  with peer keyring under CapEnter; peer push succeeds with journal/audit/plan
  and ≥1 `auth.peer.admit` (M3p + M2j)
- **M3z:** FreeBSD StrictLaunch CapEnter M2j apply RestartOne — peer keyring;
  kill apply; net+auth+index + listen survive; apply+journal+audit respawn;
  ≥2 `auth.peer.admit` (M3r under M2j)
- **M4a:** FreeBSD StrictLaunch CapEnter M2j parser-down RestartOne — peer
  keyring; kill parser; net+auth + listen survive;
  parser→plan→index→apply→journal→audit respawn; ≥2 `auth.peer.admit` (M3u
  under M2j)
- **M4b:** FreeBSD StrictLaunch CapEnter M2j peer deny/admit — unknown peer and
  wrong-key rejected without destination mutation; valid peer push admits with
  `auth.peer.deny` + `auth.peer.admit` (M2i under CapEnter StrictLaunch)
- **M4c:** Darwin/OpenBSD anon key FD residual — `CreateKeyFD` stays
  anon-unlinked O_RDONLY; `DISC-KEY-FD` Unavailable; sealed path remains
  Linux/FreeBSD only
- **M4d:** release-mode `Confine` fails closed unless ambient AF_INET is
  denied for non-network roles (`RequireAmbientRoleNetDenied` /
  `NEG-ROLE-NET`) on Linux/Darwin/OpenBSD; FreeBSD no-op (M3s residual)
- **M4e:** Darwin StrictLaunch Seatbelt push first cut — StrictLaunch Once
  under `sandbox_init` (cgo) completes push with journal/audit/plan (M3p
  Darwin parity)
- **M4f:** Darwin StrictLaunch Seatbelt RestartOne apply — kill apply; net +
  listen survive; apply+journal+audit respawn under fail-closed confine;
  second push succeeds (M3r Darwin parity)
- **M4g:** Darwin StrictLaunch Seatbelt parser-down RestartOne — kill parser;
  net+auth + listen survive; parser→plan→index→apply→journal→audit respawn;
  second push succeeds (M3u Darwin parity)
- **M4h:** Darwin StrictLaunch Seatbelt auth-primary RestartOne — kill auth;
  net + data plane + listen survive; auth respawns with primary peer rebind;
  second push succeeds (M3v Darwin parity)
- **M4i:** Darwin StrictLaunch Seatbelt auth ExtraPeer RestartOne — peer
  keyring; kill auth; data plane + listen survive; auth respawns with primary +
  audit ExtraPeer rebind; ≥2 `auth.peer.admit` (M3w Darwin parity)
- **M4j:** Darwin StrictLaunch Seatbelt audit ExtraPeer RestartOne — peer
  keyring; kill audit; auth+upstream + listen survive; apply+journal+audit
  respawn with auth ExtraPeer→audit rebind; ≥2 `auth.peer.admit` (M3x Darwin
  parity)
- **M4k:** Darwin StrictLaunch Seatbelt peer-key push — StrictLaunch Once with
  peer keyring under Seatbelt; peer push succeeds with journal/audit/plan and
  ≥1 `auth.peer.admit` (M3y Darwin parity)
- **M4l:** Darwin StrictLaunch Seatbelt peer deny/admit — unknown peer and
  wrong-key rejected without destination mutation; valid peer push admits with
  `auth.peer.deny` + `auth.peer.admit` (M4b Darwin parity)
- **M4m:** Darwin StrictLaunch Seatbelt peer apply RestartOne — peer keyring;
  kill apply; net+auth+index + listen survive; apply+journal+audit respawn;
  ≥2 `auth.peer.admit` (M3z Darwin parity)
- **M4n:** Darwin StrictLaunch Seatbelt peer parser-down RestartOne — peer
  keyring; kill parser; net+auth + listen survive;
  parser→plan→index→apply→journal→audit respawn; ≥2 `auth.peer.admit` (M4a
  Darwin parity)
- **M4o:** Linux StrictLaunch Landlock+seccomp push first cut — StrictLaunch
  Once under Landlock+seccomp completes push with journal/audit/plan (M3p/M4e
  Linux parity)
- **M4p:** Linux StrictLaunch Landlock+seccomp RestartOne apply — kill apply;
  net+auth+index + listen survive; apply+journal+audit respawn; second push
  succeeds (M3r/M4f Linux parity)
- **M4q:** Linux StrictLaunch Landlock+seccomp RestartOne parser-down — kill
  parser; net+auth + listen survive; parser→plan→index→apply→journal→audit
  respawn; second push succeeds (M3u/M4g Linux parity)
- **M4r:** Linux StrictLaunch Landlock+seccomp RestartOne auth-primary — kill
  auth; net + full data plane + listen survive; auth respawns; second push
  succeeds (M3v/M4h Linux parity)
- **M4s:** Linux StrictLaunch Landlock+seccomp RestartOne auth ExtraPeer —
  peer keyring; kill auth; net + full data plane + listen survive; auth
  respawns with ExtraPeer rebind; ≥2 `auth.peer.admit` (M3w/M4i Linux parity)
- **M4t:** Linux StrictLaunch Landlock+seccomp RestartOne audit ExtraPeer —
  peer keyring; kill audit; auth+net+parser+plan+index + listen survive;
  apply+journal+audit respawn; ≥2 `auth.peer.admit` (M3x/M4j Linux parity)
- **M4u:** Linux StrictLaunch Landlock+seccomp peer-key Once push — peer
  keyring completes push with journal/audit/plan and ≥1 `auth.peer.admit`
  (M3y/M4k Linux parity)
- **M4v:** Linux StrictLaunch Landlock+seccomp peer deny/admit — unknown peer
  and wrong-key rejected without destination mutation; valid peer push admits
  with `auth.peer.deny` + `auth.peer.admit` (M4b/M4l Linux parity)
- **M4w:** Linux StrictLaunch Landlock+seccomp peer apply RestartOne — peer
  keyring; kill apply; net+auth+index + listen survive; apply+journal+audit
  respawn; ≥2 `auth.peer.admit` (M3z/M4m Linux parity)
- **M4x:** Linux StrictLaunch Landlock+seccomp peer parser-down RestartOne —
  peer keyring; kill parser; net+auth + listen survive;
  parser→plan→index→apply→journal→audit respawn; ≥2 `auth.peer.admit`
  (M4a/M4n Linux parity); completes Linux Landlock campaign M4o–M4x
- **M4y:** OpenBSD StrictLaunch pledge+unveil push first cut — OpenBSD CI VM;
  StrictLaunch Once under unveil-then-pledge completes push with
  journal/audit/plan; broad first-cut promises (no `tmppath`);
  DISC-PLEDGE/DISC-UNVEIL Available (M3p/M4e/M4o OpenBSD parity)
- At commit, index scans the destination readonly and confers a dest manifest so
  apply’s `localsync.Sync` skips `Scan(destination)`
- Same wire protocol as `integris push` / monolithic `integris serve` (shared PSK
  path unchanged when `-key`/`-keyfile` is used)

## Explicitly not supported

- Product IC-1 release mode / PKI (M2k `-strict-launch` is an engineering preview only)
- Broader Capsicum object rights / path allow-lists beyond archive allow-root FDs
- PKI / long-term node identity / trust anchors
- Bidirectional sync, deletions, multi-client scheduling
- Claiming IC-1 exit or production readiness
- Multiple ExtraPeer endpoints beyond the pairs above
- Index without plan/journal/audit in this engineering slice

## CLI

```sh
# Shared PSK (M2h default chain)
go run ./cmd/integrisd serve -destination ./B -key "$HEX32" -addr 127.0.0.1:9100
go run ./cmd/integris push -source ./A -addr 127.0.0.1:9100 -key "$HEX32"

# Per-peer PSK allow-list (M2i)
go run ./cmd/integrisd serve -destination ./B \
  -peer-key alice=./alice.key -peer-key bob=./bob.key -addr 127.0.0.1:9100
go run ./cmd/integris push -source ./A -addr 127.0.0.1:9100 \
  -keyfile ./alice.key -peer alice

# Strict / release-shaped launch (M2k; still not IC-1 product release)
go run ./cmd/integrisd serve -destination ./B -key "$HEX32" \
  -addr 127.0.0.1:9100 -strict-launch
```

Library topology flags: `DisableAuth`, `DisableParser`, `DisableAudit`,
`DisableJournal`, `DisablePlan`, `DisableIndex` (tests / embedders).
`ServeOptions.Peers` is mutually exclusive with `RootKey`; peer keyring requires auth.

## Authority notes (M2h + M2i)

| Role | Holds | Must not |
|---|---|---|
| auth | push root key or INTPEER1 keyring | network accept, archive bytes |
| net | TCP + sealed AEAD | push root key, archive roots |
| parser | bounded message validate | permanent keys, archives, network |
| plan | canonical manifests / plan output | filesystem writes, network, keys |
| index | readonly archive root, bounded index output | network, publication, deletion |
| apply | destination allow-roots | network; journal descriptor |
| journal | journal descriptor | policy, network, archive mutation |
| audit | redacted event sink | secrets, archives, operation decisions |

## Layout on destination

| Path | Owner |
|---|---|
| `.integris/recv-partial/` | apply |
| `.integris/recv-stage/` | apply |
| `.integris/local.jrn` | journal |
| `.integris/last-plan.json` | apply |
| `.integris/audit.events` | audit |

## Next increment (proposed)

FreeBSD ambient AF_INET deny compatible with allow-root CapRightsLimit,
broader product authz / PKI, or IC-1 evidence campaigns.
