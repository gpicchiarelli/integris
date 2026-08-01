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
- argv/env limited to role, peer, session nonce (non-secret);
- MAC key conferred on **fd 4** via a pipe (`ExtraFiles[1]`), never via
  environment;
- IPC socket on **fd 3** (`ExtraFiles[0]`);
- a finite `context` deadline for wait;
- `EngineeringMode=true` required; when false, Start refuses (release path not
  yet implemented).

No `/bin/sh`, no interpolated command lines, no `PATH` search for the executable
(caller supplies an absolute path). Working directory is set to an empty temp
directory owned for the test/run.

### Explicit non-decisions (deferred)

- Full platform confinement matrix (Capsicum, Landlock path allow-lists, Hardened
  Runtime entitlements, seccomp-BPF). Engineering children call
  `confine.ApplyEngineering` (Linux: `no_new_privs` + empty Landlock ruleset;
  OpenBSD: `pledge("stdio unix")` + `unveil` lock).
- Sealed MAC key transport (memfd/SCM_RIGHTS only; pipe fd is engineering-only).
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

## Risk analysis

Mitigates uncontrolled subprocess creation outside a single adapter. Residual:
engineering MAC key still traverses a pipe readable by a compromised sibling with
access to the child's fd table before close; acceptable only for development/tests.
Common-cause: compromised supervisor still controls children. Complexity: one new
package and stub binary.

## Compatibility and portability

Unix-only for this revision (`//go:build unix`). Other platforms remain refused.

## Verification strategy and acceptance criteria

- Unit: refuse non-absolute path, refuse `EngineeringMode=false`, refuse empty
  socket, wait deadline.
- Integration: parent↔stub authenticated IPC over conferred socketpair fd.
- Residual gaps recorded on EVD-ARCH-001 until confinement probes pass in-child.

## Retirement/rollback plan

Superseding IP removes env key conferral and requires sealed key + confinement
before `EngineeringMode` can be false. Stub binary can be deleted without format
churn.

## Dissent and unresolved questions

- Exact fd number ABI (currently ExtraFiles → fd 3 IPC, fd 4 key pipe).
- Whether release builds embed role binaries or invoke verified install paths.

## Decision and approvals

Draft — unlocks engineering spawn only; independent security review still
required before IC-1 authority evidence promotion.
