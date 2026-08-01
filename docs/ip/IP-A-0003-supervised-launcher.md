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

- `ExtraFiles` containing exactly the conferred IPC socket end(s);
- argv/env limited to role, peer, session nonce, and key-transport label
  (non-secret);
- MAC key conferred on **fd 4** via `CreateKeyFD` (`ExtraFiles[1]`), never via
  environment (default ABI):
  - **Linux:** sealed `memfd` (`F_SEAL_WRITE|SHRINK|GROW|SEAL`);
  - **other Unix:** unlinked temp file reopened `O_RDONLY` (engineering residual
    until memfd seals land);
- optional `KeyViaSCM`: ExtraFiles is socket-only; parent sends the key FD with
  `SCM_RIGHTS` (`ipc.SendFD`) before the first authenticated frame;
- IPC socket on **fd 3** (`ExtraFiles[0]`);
- a finite `context` deadline for wait;
- `EngineeringMode=true` required; when false, Start refuses (release path not
  yet implemented).

No `/bin/sh`, no interpolated command lines, no `PATH` search for the executable
(caller supplies an absolute path). Working directory is set to an empty temp
directory owned for the test/run.

### Explicit non-decisions (deferred)

- Full platform confinement matrix (dedicated accounts, Hardened Runtime
  entitlements, fine-grained Landlock path allow-lists, FreeBSD
  `cap_rights_limit`). Engineering children call `confine.ApplyEngineering`
  (Linux: `no_new_privs` + empty Landlock ruleset + seccomp exec/ptrace denylist;
  OpenBSD: `pledge("stdio unix")` + `unveil` lock; FreeBSD: `cap_enter`).
  Stubs report `NegativeEngineering` (`NEG-FS-OPEN`, `NEG-EXEC`, `NEG-PTRACE`)
  and role-semantic conferral probes (`NEG-NET-ARCHIVE`, `NEG-PARSER-NET`) over IPC.
- SCM_RIGHTS key passing over the IPC socket (optional `KeyViaSCM`; fd-4 ExtraFiles
  remains the default ABI). Underlying FD may still be memfd/anon-unlinked.
- Darwin/FreeBSD/OpenBSD memfd-equivalent seals (anon-unlinked residual).
- Remaining role-semantic probes (`NEG-PLAN-WRITE`, `NEG-AUDIT-DECIDE`,
  `NEG-JOURNAL-NET`) and OS-level role denials beyond conferral inventory.
- Multi-child restart policy and supervisor crash recovery beyond
  `supervisor.Runtime` kill-on-Close.
- Windows process model.

### Role stub

`cmd/integris-role-stub` is an engineering helper that speaks one authenticated
IPC request/response on fd 3 and exits. It is not a product daemon and must not
appear in release acceptance evidence as a runtime component.

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
  reports `|KEY:` transport and `|NEG-FS:`/`|NEG-EXEC:`/`|NEG-PTRACE:` statuses.
- Residual gaps recorded on EVD-ARCH-001 until confinement probes pass in-child
  and non-Linux sealed transport reaches parity.

## Retirement/rollback plan

Superseding IP requires sealed key + confinement on all release platforms before
`EngineeringMode` can be false. Stub binary can be deleted without format churn.

## Dissent and unresolved questions

- Exact fd number ABI (currently ExtraFiles → fd 3 IPC, fd 4 key FD).
- Whether release builds embed role binaries or invoke verified install paths.

## Decision and approvals

Draft — unlocks engineering spawn only; independent security review still
required before IC-1 authority evidence promotion.
