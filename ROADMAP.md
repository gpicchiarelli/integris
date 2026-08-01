# Roadmap and entrance gates

Progress is evidence-gated, not date-gated. A milestone is complete only after
its acceptance criteria are met and independently approved.

## M0 — Assurance baseline

- criticality policy and claim boundaries;
- preliminary hazard analysis and threat model;
- foundational requirements and invariants;
- security architecture and authority map;
- transaction, journal, protocol, filesystem, and cryptographic specifications;
- Go profile, platform matrix, verification plan, and governance;
- automated referential-integrity and traceability checks.

Exit: no orphan requirement, hazard, threat, verification method, or evidence
record; formal models pass; two independent approvers accept every IC-1 item.

**Status:** baseline artifacts are complete; independent IC-1 approvers and
hosting branch-protection evidence remain open (see `docs/github-settings.md`).

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
(Darwin, cgo); stub reports NEG-FS/EXEC/PTRACE and full role-semantic conferral
NEG-*; Runtime orchestrates spawn; sealed MAC key FD (Linux memfd; anon-unlinked
elsewhere) with optional SCM_RIGHTS; provisional session AEAD with suite
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
with transcript-bound keys, mutual provisional HMAC peer-auth (`i2r`+`r2i`), and
archive-auth proofs exist; Noise/TLS handshake and PQ remain open.

Exit: independent protocol/cryptographic review and published test vectors.

## M4 — Release candidate

- reproducible artifacts, SBOMs, signatures, and SLSA provenance;
- operator, recovery, upgrade, rollback, revocation, and retirement procedures;
- an independent rebuild and all release evidence.

No stable release exists until every criterion in `docs/release-policy.md` is met.
