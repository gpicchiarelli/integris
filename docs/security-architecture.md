# Security architecture

Status: **Normative architecture baseline**
Decision: [IP-A-0001](ip/IP-A-0001-privilege-separation.md)

Logical components, lifecycle, concurrency, and acyclic dependency rules are
defined in
[specifications/daemon-architecture.md](specifications/daemon-architecture.md)
(INT-ARCH-0001). This document remains the normative **process authority map**;
INT-ARCH-0001 places components into these roles and MUST NOT widen them.

## Processes and authority

| Process | May hold | Must not hold |
|---|---|---|
| `integrisd-supervisor` | child lifecycle, pre-opened IPC endpoints, policy identity | remote content parser, archive traversal, long-term keys |
| `integrisd-net` | connected/listening network sockets, bounded encrypted frames | archive descriptors, permanent keys, journal writes |
| `integrisd-auth` | identity handle, session key derivation, authorization policy | network accept loop, archive contents, publication rights |
| `integrisd-parser` | bounded message input/output IPC | permanent keys, archives, network sockets |
| `integrisd-index` | read-only archive root, bounded index output | network, publication, deletion |
| `integrisd-plan` | canonical manifests/capabilities, plan output | filesystem writes, network, keys |
| `integrisd-apply` | pre-opened archive/staging/quarantine roots | network, identity keys, arbitrary path lookup |
| `integrisd-journal` | journal descriptor, authenticated record input | policy decisions, network, archive mutation |
| `integrisd-audit` | read-only journal and redacted event sink | operation decisions, archives, secrets |

Package boundaries are not security boundaries. Each component is a separate OS
process with independently reduced authority. Descriptors and IPC endpoints are
conferred explicitly; inheritance defaults closed.

## Local IPC contract

Every channel has a fixed peer role, protocol version, session nonce, monotonic
sequence, maximum frame and queue size, request deadline, explicit close, and
authenticated message context. Unknown critical messages, duplicate sequences,
quota exhaustion, role mismatch, or authentication failure close the channel and
record a security event. Local authentication prevents confused-deputy behavior;
it is not a substitute for OS isolation.

## Trust boundaries

1. hostile network to `net`;
2. decoded remote input from `parser` to decision components;
3. authorization decision from `auth` to `plan`/`apply`;
4. immutable plan from `plan` to `apply`;
5. archive root and staging/quarantine descriptors at `apply`;
6. untrusted operational events to `audit`;
7. build/release infrastructure to operator-installed artifact.

Data crossing a boundary is canonical, typed, bounded before allocation, bound to
peer/session/archive identity, and rejected on unknown security-relevant fields.

## Failure policy

Fail closed for authorization, archive identity, confinement availability,
semantic representability, journal integrity, plan mismatch, resource limits,
and destructive thresholds. Degraded operation is allowed only where a
requirement explicitly defines preserved guarantees and observable status.

## Common-cause controls

Process separation does not protect against a hostile kernel, shared library,
compiler, protocol flaw, or compromised supervisor. Controls include minimal
dependencies, no dynamic plugins, independent parsers/verifiers, native sandbox
layers, reproducible builds, provenance, fault injection, model checking, and
independent review. Residual common-cause risk remains until evidenced per
platform and release.
