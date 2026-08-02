# Assurance case

Status: **Living argument — M0 baseline**

## Top claim

**C0:** Integris can be implemented and evaluated as a high-integrity replication
system without allowing unreviewed implementation work to define its safety and
security properties after the fact.

This is an engineering claim, not a certification or product-readiness claim.

## Argument

| Claim | Argument | Current evidence |
|---|---|---|
| C1 Scope is bounded | Claims, non-claims, boundaries, and assumptions are explicit | `docs/scope-and-claims.md` |
| C2 Risks drive requirements | Hazards and threats link to mitigating requirements | `assurance/hazards.json`, `assurance/threats.json` |
| C3 Requirements are verifiable | Every requirement links to specifications, methods, evidence, owner, and approver | generated `docs/traceability.md` |
| C4 Authority is minimized | Processes and descriptors have explicit authority and denied capabilities; logical components map into those roles without widening them | `docs/security-architecture.md`, `docs/specifications/daemon-architecture.md` |
| C5 Core behavior is precise | Protocol (INT-PROTO-0001), path, journal, transaction, configuration, and filesystem semantics are specified | `docs/specifications/`, esp. `replication-protocol.md` |
| C6 Critical invariants are modelled | Session and transaction models state checkable safety properties | `formal/` |
| C7 Implementation is constrained | Restricted Go profile and verification plan prohibit common integrity failures | `docs/go-profile.md`, `docs/verification-plan.md` |
| C8 Release claims are evidence-gated | Stable release requires platform, recovery, provenance, signature, and reproducibility evidence | `docs/release-policy.md` |
| C9 Native platform capacity is used | Every declared OS exercises qualifying stable native optimizations (INT-IC4-0001) | `docs/specifications/platform-optimization.md`, `docs/platform-matrix.md` |

## Defeaters and gaps

- Formal models are abstractions; conformance tests must connect them to code.
- No specialist cryptographic review has occurred.
- Platform confinement and filesystem behavior need versioned empirical evidence.
- Independent reviewers and code owners must be assigned by the hosting project.
  As of 2026-08-01 only `gpicchiarelli` is assigned (interim record ownership /
  maintainer / interim release manager). Technical reviewer, security reviewer,
  independent assurance owner, and cryptography reviewer remain **unassigned**;
  inventing fake independent reviewers is prohibited. This blocks M0 exit and
  independent IC-1 approval (see `GOVERNANCE.md`).
- Reproducibility requires two independent builders and cannot be established by
  the author repeating a build locally.
- GitHub branch protection, private reporting, and environments are external
  settings and cannot be guaranteed by files in this repository alone. Probe on
  2026-08-01 (evening): `main` has branch protection with required status
  checks and `enforce_admins`; secret scanning + push protection, Dependabot
  security updates, private vulnerability reporting, and Actions SHA pinning
  are enabled; `.github/CODEOWNERS` is present. Residual: independent IC-1
  reviewers still unassigned; required code-owner review deferred until a
  second owner exists (see `docs/github-settings.md`).

These are release blockers where `docs/release-policy.md` says so. The assurance
case must never convert planned evidence into produced evidence.
