# Governance

## Roles

- **Maintainer** administers the repository and accepts non-critical changes.
- **Technical reviewer** verifies correctness and maintainability.
- **Security reviewer** verifies threat coverage and fail-safe behavior.
- **Assurance owner** accepts traceability and release evidence.
- **Release manager** assembles but cannot solely approve a release.

One person may hold several roles, except that an author cannot be the sole
approver of an IC-1 change or release. IC-1 changes require explicit approval
from a technical reviewer, security reviewer, and assurance owner. At least one
approval must be independent of the author.

## Current assignment (Sprint 0)

Recorded 2026-08-01 for the private repository `gpicchiarelli/integris`.
Assurance `owner` fields name the accountable person; `approver_roles` and
evidence `reviewer_role` values remain governance role identifiers (not people).

| Role | Assignee | Status |
|---|---|---|
| Maintainer | `gpicchiarelli` | Assigned |
| Technical reviewer | — | **Unassigned** |
| Security reviewer | — | **Unassigned** |
| Assurance owner (independent IC-1 approval) | — | **Unassigned** |
| Assurance record ownership (interim) | `gpicchiarelli` | Assigned as signed interim owner of assurance records |
| Release manager | `gpicchiarelli` | Interim only; cannot solely approve a release |
| Cryptography reviewer | — | **Unassigned** (required before protocol/crypto evidence acceptance) |

**Residual M0 process gap:** no independent technical, security, or assurance
approver exists. `gpicchiarelli` is the sole author and cannot satisfy ROADMAP
M0 exit (“two independent approvers accept every IC-1 item”) or GOVERNANCE
independence alone. Do not invent placeholder reviewer identities. Product-kernel
merges remain gated until real independent reviewers are assigned. `CODEOWNERS`
is intentionally absent until those people exist (see `docs/github-settings.md`).

## Decision process

Durable technical decisions use an Integris Proposal (IP) in `docs/ip/`.
Categories are: `IP-A` architecture, `IP-P` protocol, `IP-F` persistent format,
`IP-S` security and safety, `IP-C` cryptography, `IP-O` operations, and `IP-G`
governance. The template is `docs/ip/000-template.md`.

An IP records status, motivation, requirements, alternatives, risk analysis,
compatibility, migration, verification, retirement, decision, and dissent.
Rejected alternatives remain in history. Silent exceptions are prohibited.

## Change control

Every pull request declares criticality, affected requirement IDs, affected
hazard/threat IDs, verification evidence, and reviewer roles. Emergency changes
use the same controls; urgency can shorten elapsed time, never required evidence.

## Conflict and appeal

Technical objections are recorded in the IP or pull request. The assurance owner
may veto a release for missing evidence. A veto is lifted only by satisfying the
stated acceptance criterion or by an approved IP that changes the criterion and
documents the new residual risk.
