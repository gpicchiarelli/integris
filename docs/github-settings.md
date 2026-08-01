# Required GitHub repository settings

Repository files cannot enforce hosting settings. Before accepting contributions,
an administrator records screenshots/API evidence that `main` has:

- deletion and force-push disabled;
- pull requests required with at least two approvals for IC-1 changes;
- stale approvals dismissed and code-owner review required after owners exist;
- all conversations resolved;
- CI, formal models, CodeQL, and dependency review required as applicable;
- administrators subject to the same rules, with emergency bypass logged;
- secret scanning, push protection, private vulnerability reporting, Dependabot
  alerts, and dependency graph enabled;
- Actions restricted to trusted/pinned actions and read-only default token;
- release environments requiring independent approval and no untrusted PR access;
- immutable releases enabled when the GitHub plan supports them.

Do not add a placeholder `CODEOWNERS`: a nonexistent user/team creates a false
control. Add the file only after real technical, security, and assurance owners
are assigned, then make it a required review source.

For private repositories without GitHub Advanced Security, the CodeQL workflow
MUST run analysis with SARIF and database uploads set to `never`/`false`, and
preserve its SARIF as a short-lived workflow artifact. Enabling dashboard upload
and secret-scanning controls remains an external prerequisite when the required
GitHub plan becomes available.
GitHub Dependency Review is also unavailable in that configuration; the private
fallback verifies the Go module graph and reachable vulnerabilities but does not
claim equivalent dependency-diff or license-policy coverage.

## Evidence snapshot (2026-08-01)

Probed with `gh` as repository admin on private `gpicchiarelli/integris`.
Values below are observations, not claims that controls are satisfied.

| Control | Observed | Notes |
|---|---|---|
| Default branch | `main` | Confirmed via repo API |
| Branch protection on `main` | **Not enabled** | `GET .../branches/main` → `protected: false` |
| Branch protection rules API | **Unavailable** | `GET .../branches/main/protection` → HTTP 403 (“Upgrade to GitHub Pro or make this repository public”) |
| Repository rulesets API | **Unavailable** | HTTP 403 (same plan limitation) |
| Force-push / deletion blocks | **Not evidenced** | Cannot be confirmed without protection/rulesets |
| Required PR reviews / status checks | **Not evidenced** | Same |
| `CODEOWNERS` | Absent by design | No real independent owners yet; see `GOVERNANCE.md` |
| Vulnerability / Dependabot alerts | **Disabled** | `GET .../vulnerability-alerts` → HTTP 404 |
| Secret scanning | **Disabled** | Alerts API → HTTP 404 |
| Actions | Enabled | `allowed_actions: all`, `sha_pinning_required: false` (weaker than required) |
| Merge policy | Squash-only | `allow_squash_merge: true`; merge/rebase commits disabled; `delete_branch_on_merge: true` |

**Residual hosting gap:** branch protection, required reviews, secret scanning,
Dependabot alerts, Action pinning, and release environments are not in place (or
not inspectable) on the current private/free plan. Enabling them is an external
admin action and an M0 process blocker alongside independent reviewer assignment.
