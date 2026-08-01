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

- `ExtraFiles` containing the conferred IPC socket end(s) (socket-only by default);
- argv/env limited to role, peer, session nonce, key-transport label, optional
  confer/slot inventory, and optional `INTEGRIS_ALLOW_ROOTS` (non-secret);
- `supervisor.Runtime.AllowRoots` forwards absolute archive roots into
  `launcher.Start` for Apply/Index engineering probes;
- `INTEGRIS_STUB_MODE=initiate|respond` for child↔child IPC (StartPair/RestartPair);
- dual-live edges require `KeyViaExtraFiles` (SCM dual-spawn unsupported);
- MAC key via `CreateKeyFD`, never via environment:
  - **default ABI:** ExtraFiles is socket-only (IPC on **fd 3**); parent sends the
    key FD with `SCM_RIGHTS` (`ipc.SendFD` on `Handle.KeyFD`) before the first
    authenticated frame;
  - **legacy opt-in** (`KeyViaExtraFiles`): key on **fd 4** (`ExtraFiles[1]`);
  - **Linux:** sealed `memfd` (`F_SEAL_WRITE|SHRINK|GROW|SEAL`);
  - **other Unix:** unlinked temp file reopened `O_RDONLY` (engineering residual
    until memfd seals land);
- a finite `context` deadline for wait;
- `EngineeringMode=true` required; when false, Start refuses (release path not
  yet implemented).

No `/bin/sh`, no interpolated command lines, no `PATH` search for the executable
(caller supplies an absolute path). Working directory is set to an empty temp
directory owned for the test/run.

### Explicit non-decisions (deferred)

- Full platform confinement matrix (dedicated accounts, Hardened Runtime
  entitlements, fine-grained Landlock path allow-lists, FreeBSD
  `cap_rights_limit` object rights beyond conferred fds). Engineering children
  call `confine.ApplyEngineeringOpts(role, opts)`:
  - Linux: `no_new_privs` + Landlock (empty or path_beneath allow-roots for
    Apply/Index) + seccomp exec/ptrace denylist; roles without `network_sockets`
    also deny socket/connect/bind/listen/accept*;
  - OpenBSD: role-parameterized `pledge` + `unveil` of allow-roots then lock;
  - FreeBSD: `cap_enter` (fd-only; path allow-lists require conferred directory FDs);
  - Darwin: Seatbelt `sandbox_init` via cgo (`deny network*` unless net role;
    archive roles may receive `(allow file-read*/file-write* (subpath …))`
    allow-roots — EvalSymlinks required; `NEG-FS-PATH` asserts open under root;
    `NEG-FS-WRITE` asserts create under root succeeds for Apply and is denied for Index).
  Stubs report `NegativeEngineering` (`NEG-FS-OPEN`, `NEG-FS-READ`, `NEG-FS-PATH`,
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
- Legacy ExtraFiles fd4 key path remains available via `KeyViaExtraFiles` for
  engineering callers that cannot yet SendFD after spawn.
- Darwin App Sandbox / Hardened Runtime / launchd identities (Seatbelt engineering
  apply is not claimed equivalent).
- Darwin/FreeBSD/OpenBSD memfd-equivalent seals (anon-unlinked residual).
- Broader role path allow-lists beyond Apply/Index archive caps; pre-conferred
  directory FDs on FreeBSD Capsicum.
- Dual-live crash recovery beyond kill-both `RestartPair` (in-place peer FD
  rebind while one child survives; SCM dual-spawn still unsupported).
- Windows process model.

### Role stub

`cmd/integris-role-stub` is an engineering helper that speaks one authenticated
IPC request/response on fd 3 and exits. It is not a product daemon and must not
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
