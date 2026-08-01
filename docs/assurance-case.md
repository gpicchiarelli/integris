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
| C4 Authority is minimized | Processes and descriptors have explicit authority and denied capabilities | `docs/security-architecture.md` |
| C5 Core behavior is precise | Protocol, path, journal, transaction, configuration, and filesystem semantics are specified | `docs/specifications/` |
| C6 Critical invariants are modelled | Session and transaction models state checkable safety properties | `formal/` |
| C7 Implementation is constrained | Restricted Go profile and verification plan prohibit common integrity failures | `docs/go-profile.md`, `docs/verification-plan.md` |
| C8 Release claims are evidence-gated | Stable release requires platform, recovery, provenance, signature, and reproducibility evidence | `docs/release-policy.md` |

## Defeaters and gaps

- Formal models are abstractions; conformance tests must connect them to code.
- No specialist cryptographic review has occurred.
- Platform confinement and filesystem behavior need versioned empirical evidence.
- Independent reviewers and code owners must be assigned by the hosting project.
- Reproducibility requires two independent builders and cannot be established by
  the author repeating a build locally.
- GitHub branch protection, private reporting, and environments are external
  settings and cannot be guaranteed by files in this repository.

These are release blockers where `docs/release-policy.md` says so. The assurance
case must never convert planned evidence into produced evidence.
