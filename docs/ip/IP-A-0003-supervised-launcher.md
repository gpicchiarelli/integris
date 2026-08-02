# IP-A-0003: Isolated supervised child launcher

- Status: Draft
- Category: IP-A
- Authors: Integris maintainers
- Reviewers: technical, security, assurance
- Created: 2026-08-01
- Supersedes:
- Requirements: INT-IC1-0001, INT-IC3-0001
- Anchors: `docs/security-architecture.md`, `docs/go-profile.md`, IP-A-0001, IP-A-0002
- Unlocks: `internal/launcher`, `cmd/integris-role-stub` (engineering)

## Motivation

M2 privilege separation requires the supervisor to start child role processes with
pre-opened IPC descriptors. The Go profile prohibits ambient `os/exec` in product
kernels. Without a narrow, reviewed exception, socketpair fabrics cannot cross a
process boundary and negative capability probes cannot run in confined children.

## Decision drivers and requirements

- IP-A-0001: OS process boundaries; descriptors conferred explicitly.
- Go profile: no shell, no plugins; any exec surface must be isolated and IP-gated.
- INT-IC3-0001: startup refuses missing confinement for release modes.
- Children must not inherit ambient file descriptors or an open authority set.

## Proposed decision

### Package boundary

Among packages under `internal/`, only `internal/launcher` may import `os/exec`
(and related process-start APIs). Other `internal/*` packages must not start
subprocesses. Engineering CLIs under `cmd/integris-*` may invoke host `git` /
`go` for evidence and build tooling only; they are not a child-role launcher.

CI/reviewers treat `os/exec` imports in `internal/` outside `launcher` as a
profile defect.

### Engineering launch mode (this IP revision)

`launcher.Start` may start a single absolute executable with:

- `ExtraFiles` containing the conferred IPC socket end(s) (socket-only by default;
  FreeBSD also appends opened allow-root directory FDs when
  `INTEGRIS_ALLOW_ROOTS` is set, addressed by `INTEGRIS_ALLOW_ROOT_FDS`);
- argv/env limited to role, peer, session nonce, key-transport label, optional
  confer/slot inventory, and optional `INTEGRIS_ALLOW_ROOTS` (non-secret);
- `supervisor.Runtime.AllowRoots` forwards absolute path roots into
  `launcher.Start` for Apply/Index/Journal/Audit engineering probes;
  confer/slot inventory, and optional `INTEGRIS_ALLOW_ROOTS` /
  `INTEGRIS_ALLOW_ROOT_FDS` (non-secret);
- `supervisor.Runtime.AllowRoots` forwards absolute archive roots into
  `launcher.Start` for Apply/Index engineering probes;
- `RestartChild` reuses `Runtime.AllowRoots` for the respawned role (same
  path allow-list as the initial `StartChild`);
- `INTEGRIS_STUB_MODE=initiate|respond` for child↔child IPC (StartPair/RestartPair);
- dual-live edges use default SCM key-channel conferral (M2m); each child has its
  own `Handle.KeyChannel` so fabric peer ends are not needed for SendFD;
- `RestartOne` (M2n): kill one dual-live end, `ReplacePair`, respawn, confer the
  new peer IPC FD to the survivor via `SendPeerFDFile` (`PeerFDMagic`) on the
  still-open key channel; stub `hold-initiate`/`hold-respond` + `RDY1` sync;
- MAC key via `CreateKeyFD`, never via environment:
  - **default ABI (M2l/M2m):** ExtraFiles = IPC on **fd 3**, dedicated key-channel
    socket on **fd 4**, optional ExtraPeer IPC on **fd 5**, then allow-roots;
    parent confers MAC (and optional root/extra MAC) with `SCM_RIGHTS` via
    `ipc.SendFDFile(Handle.KeyChannel, Handle.KeyFD/…)` before the first
    authenticated frame; `StartPair` / `RestartPair` use this path by default;
  - **legacy opt-in** (`KeyViaExtraFiles`): key on **fd 4** (`ExtraFiles[1]`);
  - **Linux / FreeBSD:** sealed anonymous FD (`F_SEAL_WRITE|SHRINK|GROW|SEAL`;
    Linux `memfd_create`, FreeBSD `shm_open2`+`F_ADD_SEALS`);
  - **Darwin / OpenBSD:** unlinked temp file reopened `O_RDONLY` (engineering
    residual until memfd seals land);
- a finite `context` deadline for wait;
- Exactly one of `EngineeringMode` or `ReleaseMode` (M2k) required; when both
  false or both true, Start refuses. `ReleaseMode` sets
  `INTEGRIS_LAUNCH_MODE=release` for fail-closed child confinement checks
  (`integrisd -strict-launch`, including FreeBSD CapMode M3m, Capsicum
  rights-limit M3n/M3o, ambient FS-read deny M3q, CapEnter RestartOne
  first cut M3r, FreeBSD ambient AF_INET residual documented M3s, FreeBSD
  sealed MAC key FD M3t, FreeBSD CapEnter parser-down RestartOne M3u, and
  FreeBSD CapEnter auth-primary RestartOne M3v, FreeBSD CapEnter M2j
  auth ExtraPeer RestartOne M3w, and FreeBSD CapEnter M2j audit ExtraPeer
  RestartOne M3x, FreeBSD CapEnter M2j peer-key push M3y, and FreeBSD CapEnter
  M2j apply RestartOne M3z, and FreeBSD CapEnter M2j parser-down RestartOne
  M4a, FreeBSD CapEnter M2j peer deny/admit M4b, Darwin/OpenBSD anon key
  FD residual M4c, non-FreeBSD release ambient ROLE-NET deny M4d, and Darwin
  StrictLaunch Seatbelt push first cut M4e, and Darwin StrictLaunch Seatbelt
  RestartOne apply M4f, and Darwin StrictLaunch Seatbelt parser-down RestartOne
  M4g, Darwin StrictLaunch Seatbelt auth-primary RestartOne M4h, and Darwin
  StrictLaunch Seatbelt auth ExtraPeer RestartOne M4i, and Darwin StrictLaunch
  Seatbelt audit ExtraPeer RestartOne M4j, and Darwin StrictLaunch Seatbelt
  peer-key Once push M4k, and Darwin StrictLaunch Seatbelt peer deny/admit
  M4l, Darwin StrictLaunch Seatbelt peer apply RestartOne M4m, and Darwin
  StrictLaunch Seatbelt peer parser-down RestartOne M4n, and Linux StrictLaunch
  Landlock+seccomp push first cut M4o, and Linux StrictLaunch Landlock+seccomp
  RestartOne apply M4p, and Linux StrictLaunch Landlock+seccomp RestartOne
  parser-down M4q, and Linux StrictLaunch Landlock+seccomp RestartOne
  auth-primary M4r, and Linux StrictLaunch Landlock+seccomp RestartOne auth
  ExtraPeer M4s, and Linux StrictLaunch Landlock+seccomp RestartOne audit
  ExtraPeer M4t, and Linux StrictLaunch Landlock+seccomp peer-key Once push
  M4u, and Linux StrictLaunch Landlock+seccomp peer deny/admit M4v, and Linux
  StrictLaunch Landlock+seccomp peer apply RestartOne M4w, and Linux
  StrictLaunch Landlock+seccomp peer parser-down RestartOne M4x, and OpenBSD
  StrictLaunch pledge+unveil push first cut M4y, and OpenBSD StrictLaunch
  pledge+unveil RestartOne apply M4z, and OpenBSD StrictLaunch
  pledge+unveil RestartOne parser-down M5a, and OpenBSD StrictLaunch
  pledge+unveil RestartOne auth-primary M5b, and OpenBSD StrictLaunch
  pledge+unveil RestartOne auth ExtraPeer M5c, and OpenBSD StrictLaunch
  pledge+unveil RestartOne audit ExtraPeer M5d, and OpenBSD StrictLaunch
  pledge+unveil peer-key Once push M5e, and OpenBSD StrictLaunch
  pledge+unveil peer deny/admit M5f, and OpenBSD StrictLaunch
  pledge+unveil peer apply RestartOne M5g, and OpenBSD StrictLaunch
  pledge+unveil peer parser-down RestartOne M5h); it is not a
  product
  IC-1 release claim.

No `/bin/sh`, no interpolated command lines, no `PATH` search for the executable
(caller supplies an absolute path). Working directory is set to an empty temp
directory owned for the test/run.

### Explicit non-decisions (deferred)

- Full platform confinement matrix (dedicated accounts, Hardened Runtime
  entitlements, fine-grained Landlock path allow-lists, FreeBSD
  `cap_rights_limit` object rights beyond conferred fds). Engineering children
  call `confine.ApplyEngineeringOpts(role, opts)`:
  - Linux: `no_new_privs` + Landlock (empty or path_beneath allow-roots for
    Apply/Index/Journal/Audit) + seccomp exec/ptrace denylist; roles without
    `network_sockets` also deny socket/connect/bind/listen/accept*;
  - OpenBSD: role-parameterized `pledge` + `unveil` of allow-roots then lock;
  - FreeBSD: `cap_enter` after `LimitConferredFDs` + `LimitAllowRootFDs` on
    conferred archive directory FDs (`NEG-FS-PATH`/`NEG-FS-WRITE` via
    `fstat`/`openat`);
  - Darwin: Seatbelt `sandbox_init` via cgo (`deny network*` unless net role;
    path-capable roles may receive `(allow file-read*/file-write* (subpath …))`
    allow-roots — EvalSymlinks required; `NEG-FS-PATH` asserts open under root;
    `NEG-FS-WRITE` asserts create under root succeeds for Apply/Journal and is
    denied for Index/Audit).
  Stubs report `NegativeEngineering` (`NEG-CAP-MODE`, `NEG-FS-OPEN`, `NEG-FS-READ`, `NEG-FS-PATH`,
  `NEG-FS-WRITE`, `NEG-EXEC`, `NEG-PTRACE`, `NEG-ROLE-NET`) and role-semantic conferral probes
  (`NEG-NET-ARCHIVE`, `NEG-NET-KEYS`, `NEG-NET-JOURNAL`, `NEG-PARSER-NET`,
  `NEG-PARSER-KEYS`, `NEG-PARSER-ARCHIVES`,
  `NEG-AUTH-ACCEPT`, `NEG-AUTH-CONTENTS`,
  `NEG-AUTH-PUB`, `NEG-INDEX-PUB`, `NEG-INDEX-DELETE`, `NEG-APPLY-KEYS`,
  `NEG-APPLY-PATH`, `NEG-PLAN-WRITE`, `NEG-PLAN-KEYS`, `NEG-PLAN-NET`,
  `NEG-AUDIT-DECIDE`, `NEG-AUDIT-ARCHIVES`,
  `NEG-AUDIT-SECRETS`, `NEG-JOURNAL-NET`,
  `NEG-JOURNAL-POLICY`, `NEG-JOURNAL-MUTATE`, `NEG-SUP-PARSER`, `NEG-SUP-TRAVERSE`,
  `NEG-SUP-KEYS`) over IPC.
- Legacy ExtraFiles fd4 key path remains available via `KeyViaExtraFiles`.
- Darwin App Sandbox / Hardened Runtime / launchd identities (Seatbelt engineering
  apply is not claimed equivalent).
- Darwin/OpenBSD memfd-equivalent seals (anon-unlinked residual documented in
  M4c; FreeBSD sealed
  key FD landed in M3t).
- Broader role path allow-lists beyond Apply/Index/Journal/Audit archive caps
  (FreeBSD conferred directory FDs claimed in product children as of M3c;
  index ScanAt openat landed in M3d; apply staging openat landed in M3e;
  journal reopen openat landed in M3f; apply publish ApplyAt/SyncAt landed in M3g;
  audit sink openat bootstrap landed in M3h; CapEnter receive openat chain
  proof landed in M3i; RestartOne exit-channel drain landed in M3j;
  FreeBSD CapEnter stub probe NEG-CAP-MODE landed in M3k; journal openat
  bootstrap landed in M3l; product CapEnter self-check fail-closed in release
  mode landed in M3m; product allow-root `cap_rights_limit` fail-closed in
  release mode landed in M3n; product conferred IPC/key `cap_rights_limit`
  fail-closed in release mode landed in M3o; FreeBSD supervised CapEnter push
  first cut landed in M3p; product ambient FS-read deny fail-closed in release
  mode landed in M3q; FreeBSD StrictLaunch CapEnter RestartOne first cut
  landed in M3r; FreeBSD ambient AF_INET residual documented in M3s — CapEnter
  does not deny sockets; jail ip-disable rejected with allow-root CapRightsLimit;
  FreeBSD sealed MAC key FD landed in M3t; FreeBSD StrictLaunch CapEnter
  parser-down RestartOne landed in M3u; FreeBSD StrictLaunch CapEnter
  auth-primary RestartOne landed in M3v; FreeBSD StrictLaunch CapEnter M2j
  auth ExtraPeer RestartOne landed in M3w; FreeBSD StrictLaunch CapEnter M2j
  audit ExtraPeer RestartOne landed in M3x; FreeBSD StrictLaunch CapEnter M2j
  peer-key push landed in M3y; FreeBSD StrictLaunch CapEnter M2j apply
  RestartOne landed in M3z; FreeBSD StrictLaunch CapEnter M2j parser-down
  RestartOne landed in M4a; FreeBSD StrictLaunch CapEnter M2j peer deny/admit
  landed in M4b; Darwin/OpenBSD anon key FD residual documented in M4c;
  non-FreeBSD release ambient ROLE-NET deny fail-closed landed in M4d;
  Darwin StrictLaunch Seatbelt push first cut landed in M4e; Darwin
  StrictLaunch Seatbelt RestartOne apply landed in M4f; Darwin StrictLaunch
  Seatbelt parser-down RestartOne landed in M4g; Darwin StrictLaunch Seatbelt
  auth-primary RestartOne landed in M4h; Darwin StrictLaunch Seatbelt auth
  ExtraPeer RestartOne landed in M4i; Darwin StrictLaunch Seatbelt audit
  ExtraPeer RestartOne landed in M4j; Darwin StrictLaunch Seatbelt peer-key
  Once push landed in M4k; Darwin StrictLaunch Seatbelt peer deny/admit landed
  in M4l; Darwin StrictLaunch Seatbelt peer apply RestartOne landed in M4m;
  Darwin StrictLaunch Seatbelt peer parser-down RestartOne landed in M4n;
  Linux StrictLaunch Landlock+seccomp push first cut landed in M4o; Linux
  StrictLaunch Landlock+seccomp RestartOne apply landed in M4p; Linux
  StrictLaunch Landlock+seccomp RestartOne parser-down landed in M4q; Linux
  StrictLaunch Landlock+seccomp RestartOne auth-primary landed in M4r; Linux
  StrictLaunch Landlock+seccomp RestartOne auth ExtraPeer landed in M4s; Linux
  StrictLaunch Landlock+seccomp RestartOne audit ExtraPeer landed in M4t; Linux
  StrictLaunch Landlock+seccomp peer-key Once push landed in M4u; Linux
  StrictLaunch Landlock+seccomp peer deny/admit landed in M4v; Linux
  StrictLaunch Landlock+seccomp peer apply RestartOne landed in M4w; Linux
  StrictLaunch Landlock+seccomp peer parser-down RestartOne landed in M4x;
  OpenBSD StrictLaunch pledge+unveil push first cut landed in M4y; OpenBSD
  StrictLaunch pledge+unveil RestartOne apply landed in M4z; OpenBSD
  StrictLaunch pledge+unveil RestartOne parser-down landed in M5a; OpenBSD
  StrictLaunch pledge+unveil RestartOne auth-primary landed in M5b; OpenBSD
  StrictLaunch pledge+unveil RestartOne auth ExtraPeer landed in M5c; OpenBSD
  StrictLaunch pledge+unveil RestartOne audit ExtraPeer landed in M5d; OpenBSD
  StrictLaunch pledge+unveil peer-key Once push landed in M5e; OpenBSD
  StrictLaunch pledge+unveil peer deny/admit landed in M5f; OpenBSD
  StrictLaunch pledge+unveil peer apply RestartOne landed in M5g; OpenBSD
  StrictLaunch pledge+unveil peer parser-down RestartOne landed in M5h;
  OpenBSD campaign M4y–M5h complete).
- Broader product authz / PKI beyond landed M2o–M3b selective RestartOne
  (apply/parser/auth-primary and M2j dual ExtraPeer auth↔audit).
- Windows process model.

### Role stub

`cmd/integris-role-stub` is an engineering helper that claims the MAC key
(ExtraFiles fd4 or SCM on the M2l key channel), speaks one authenticated IPC
request/response on fd 3, and exits. It is not a product daemon and must not
appear in release acceptance evidence as a runtime component.

### Crash stub

`cmd/integris-crash-stub` is an engineering helper that runs either
`recovery.FilePublisher.Publish` (`INTEGRIS_CRASH_MODE=publish`, default) or a
seeded `journal.CrashSegment` append (`mode=journal`) with `KillAt` at an
IP-S-0003 catalog label (SIGKILL). It is started via `launcher.RunEngineering`
(absolute path, no shell, `EngineeringMode` required, no parent env inherit).
Not a product daemon.

## Alternatives considered

- **Keep in-process socketpair only:** rejected for M2 evidence; no OS fault domain.
- **Permit os/exec everywhere:** rejected; recreates ambient launcher hazards.
- **cgo + posix_spawn only:** deferred; heavier and still needs an IP.
- **Pipe fd for MAC key:** superseded for Linux by sealed memfd; pipe removed from
  launcher path.

## Risk analysis

Mitigates uncontrolled subprocess creation outside a single adapter. Residual:
non-Linux key FDs lack memfd write-seals; a compromised sibling with the child's
fd table before close can still read key bytes — acceptable only for
development/tests. Common-cause: compromised supervisor still controls children.
Complexity: one new package and stub binary.

## Compatibility and portability

Unix-only for this revision (`//go:build unix`). Other platforms remain refused.

## Verification strategy and acceptance criteria

- Unit: refuse non-absolute path, refuse `EngineeringMode=false`, refuse empty
  socket, wait deadline; `CreateKeyFD` round-trip.
- Integration: parent↔stub authenticated IPC over conferred socketpair fd; stub
  reports `|KEY:` transport and `|NEG-FS:`/`|NEG-FS-READ:`/`|NEG-FS-PATH:`/
  `|NEG-FS-WRITE:`/`|NEG-EXEC:`/`|NEG-PTRACE:`/`|NEG-ROLE-NET:` statuses.
- Residual gaps recorded on EVD-ARCH-001 until confinement probes pass in-child
  and non-Linux sealed transport reaches parity.

## Retirement/rollback plan

Superseding IP requires sealed key + confinement on all release platforms before
`EngineeringMode` can be false. Stub binary can be deleted without format churn.

## Dissent and unresolved questions

- Exact fd number ABI (default: ExtraFiles → fd 3 IPC + SCM_RIGHTS key; legacy
  fd 4 ExtraFiles key path remains opt-in).
- Whether release builds embed role binaries or invoke verified install paths.

## Decision and approvals

Draft — unlocks engineering spawn only; independent security review still
required before IC-1 authority evidence promotion.
