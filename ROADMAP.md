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
(Darwin, cgo) with role-parameterized ambient network denial; stub reports
NEG-FS/FS-READ/FS-PATH/FS-WRITE/EXEC/PTRACE/ROLE-NET and role-semantic conferral NEG-*
(including complete inventory MustNot conferral probes for all nine roles; CapNetwork via NEG-ROLE-NET + conferral); Runtime
orchestrates spawn (AllowRoots→stub), RestartChild, and RestartPair (KeyViaExtraFiles + stub initiate);
Apply/Index/Journal/Audit path allow-roots (Index/Audit readonly write denial probed);
journal `CrashSegment` exercises J-APPEND-PRE/MID/POST + J-META-POST on FileSegment
with Recover round-trip; recovery-side P-* PersistIO FailAt covers STAGE/PUBLISH/CONFIRM
on FilePersist; apply-side `FilePublisher` covers stage→rename→dirsync FailAt with
Observation→Recover; OS SIGKILL at J-* and P-STAGE/P-PUBLISH labels via crash-stub
(`CrashSegment.KillAt` / `FilePublisher.KillAt`); Darwin `F_FULLFSYNC` via
`platform.SyncFile` and `clonefile` via `platform.CloneFile`→`PublishFrom`
(with sparse `SEEK_DATA`/`SEEK_HOLE` + `CopyXattr`+`CopyBSDFlags`+`CopyACL`+
`CopyResourceFork`+`CopyTimes` incl. Darwin birthtime on degraded byte-copy);
CapCOW/CapXattr/CapBSDFlags/CapSparse/CapResourceFork/CapTimes/CapACL/CapUnicode
probed in `fsmodel.ProbeScratch`;
Darwin abrupt-detach SyncFile-survive harness landed; unflushed-loss
differential host-dependent; `platform.SendFile` sendfile→socket harness on
Darwin/Linux/FreeBSD, OpenBSD unavailable);
sealed MAC key FD (Linux memfd; anon-unlinked
elsewhere) with SCM_RIGHTS default (legacy ExtraFiles fd4 opt-in); provisional session AEAD with suite
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
happy-path suite (`hostile_peer_test.go`, `multi_version_test.go`); Noise/TLS
handshake and PQ remain open.

Exit: independent protocol/cryptographic review and published test vectors.

## M4 — Release candidate

- reproducible artifacts, SBOMs, signatures, and SLSA provenance;
- operator, recovery, upgrade, rollback, revocation, and retirement procedures;
- an independent rebuild and all release evidence.

No stable release exists until every criterion in `docs/release-policy.md` is met.
