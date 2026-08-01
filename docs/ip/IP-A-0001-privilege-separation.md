# IP-A-0001: OS-enforced privilege separation

- Status: Accepted for M0 architecture
- Category: IP-A
- Authors: Integris maintainers
- Reviewers: required again before M2 implementation
- Created: 2026-08-01
- Requirements: INT-IC1-0001, INT-IC1-0002, INT-IC3-0001

## Motivation

A monolithic daemon combines hostile network parsing, identity keys, planning,
journal authority, and archive mutation. A single memory-safe logic flaw could
therefore exercise catastrophic authority.

## Decision

Adopt the process and authority map in `docs/security-architecture.md`. Enforce
boundaries with native OS primitives, explicit descriptor delegation, bounded
authenticated IPC, dedicated identities, and monotonic authority reduction.
Package separation alone is insufficient.

## Alternatives

- **Single process with Go packages:** rejected; no OS fault boundary.
- **Containers only:** rejected as the primary boundary; deployment-dependent and
  too coarse for individual authority.
- **Portable weakest-common-denominator sandbox:** rejected; silently discards
  stronger native guarantees and obscures platform gaps.
- **Microkernel-only target:** deferred; conflicts with declared platforms.

## Risk analysis

Mitigates confused deputies and compromises isolated to parser/network roles.
Residual risks include kernel, supervisor, compiler, shared protocol, and IPC
authentication flaws. More processes increase lifecycle and denial-of-service
complexity; bounded channels, explicit ownership, and system tests address it.

## Verification and migration

M2 requires per-process negative capability probes, descriptor inventories,
hostile IPC tests, crash/lifecycle tests, and exact OS-version evidence. Product
implementation cannot merge components without a superseding accepted IP-A and
equivalent or stronger evidence.

## Retirement

If a platform cannot enforce mandatory controls, support is withheld or the
component is redesigned. A development-only unconstrained mode is visibly marked
and cannot produce release evidence.
