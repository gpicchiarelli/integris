# Scope and claims policy

Status: **Normative baseline**

Owner: Assurance owner
Approval: Maintainer, technical reviewer, security reviewer

## Intended system

Integris is intended to replicate explicitly authorized filesystem archives
between mutually authenticated nodes on macOS, FreeBSD, Linux, and OpenBSD.
The protected properties are archive identity, containment, authenticity,
integrity, deterministic planning, recoverability, and truthful completion.

The current repository is the engineering system for that future product. Most
executable code validates assurance records and reference kernels. The local
CLI increment `integris sync` (`internal/localsync`) may read a caller-supplied
source directory and write a caller-supplied destination directory; it is not
the privilege-separated daemon, does not perform network replication, and does
not widen the product claims below.

## Declared claims

At this milestone, Integris claims only that:

1. foundational assurance records use stable identifiers and machine-checked
   bidirectional references;
2. critical requirements identify risks, specifications, verification methods,
   evidence status, owners, and approval roles;
3. the planned architecture denies ambient authority by design and records
   platform-specific gaps;
4. transaction and session invariants have executable formal-model baselines;
5. release criteria prohibit unsupported certification and readiness claims.

Each claim is an argument to be supported by evidence in `docs/assurance-case.md`.

## Explicit non-claims

Integris is not currently:

- certified against IEC 61508 or any other standard;
- assigned a Safety Integrity Level (SIL) or systematic capability;
- validated for a defined safety function or regulated field of use;
- production-ready, complete, interoperable, or backward compatible;
- independently audited, cryptographically reviewed, or penetration tested;
- proven to preserve every filesystem semantic on any declared platform.

IEC 61508 techniques may inform engineering discipline, but certification would
require a defined safety function, application context, complete lifecycle
evidence, competent assessment, and the applicable conformity process.

## System boundary

In scope: local archive roots explicitly conferred to the apply process; peer
identity and archive authorization; manifests, plans, journal records, staged
content, publication and recovery; local configuration and release artifacts.

Out of scope until an approved IP adds them: untrusted plugins, remote code
execution, arbitrary hooks, shell commands, cloud control planes, global
atomicity across filesystems, conflict-free multi-writer semantics, and silent
lossy metadata conversion.

## Assumptions

- the operating system kernel and hardware root of trust are not fully hostile;
- administrators can protect offline recovery material and configure accounts;
- cryptographic primitives are used through reviewed implementations;
- storage can fail, lie, reorder, truncate, or exhaust capacity;
- peers, networks, inputs, operators, and build infrastructure can be hostile;
- clock correctness is not required for safety-critical ordering.

Assumptions are not controls. Invalidated assumptions require safe refusal or a
new threat/risk analysis.
