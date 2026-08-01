# Required GitHub repository settings

Repository files cannot enforce hosting settings. Before accepting contributions,
an administrator records screenshots/API evidence that `main` has:

- deletion and force-push disabled;
- pull requests required with at least two approvals for IC-1 changes;
- stale approvals dismissed and code-owner review required after owners exist;
- all conversations resolved;
- the automated checks listed under “Required status checks” below;
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
uploads to the dashboard only when the repository is public (or GHAS is
enabled); otherwise it preserves SARIF as a short-lived workflow artifact.
GitHub Dependency Review is also unavailable in that configuration; the private
fallback verifies the Go module graph and reachable vulnerabilities but does not
claim equivalent dependency-diff or license-policy coverage. Complementary
workflow scanners (OSV, Trivy, gosec, gitleaks, Scorecard) still run and retain
artifacts.

## Required status checks (when branch protection is available)

Make these required on `main` as they become stable greens:

| Workflow / job | Role |
|---|---|
| `CI` / Verify assurance baseline | fmt, verify, race, govulncheck, profile guards |
| `CI` / Bootstrap test (ubuntu + macOS) | cross-host unit tests |
| `CI` / macOS Seatbelt (cgo) | Darwin confinement adapter |
| `CI` / Cross-compile (declared GOOS/GOARCH) | build smoke for Linux/Darwin/FreeBSD/OpenBSD |
| `CI` / Short fuzz | hostile-input kernels |
| `CI` / Coverage profile | structural coverage artifact |
| `Formal models` | TLA+ TLC |
| `CodeQL` | semantic code scanning |
| `Dependency review` | PR dependency/license gate (public) or private fallback |
| `Static analyzers` | staticcheck + gosec |
| `OSV Scanner` | OSV database |
| `SBOM` | CycloneDX / Syft inventories |
| `Secret scanning` | gitleaks (hosting secret scanning may be plan-gated) |
| `Workflow lint` | actionlint + zizmor |
| `Filesystem vulnerability scan` | Trivy fs/config/secret/license |
| `Semgrep` | OSS rule packs |
| `Typos` | identifier/docs spelling |
| `Link check` | Markdown link integrity |
| `FreeBSD` | native FreeBSD tests |
| `Reproducible builds` | dual-runner digest equality + attestations on non-PR |
| `Evidence` | campaign/digest regeneration + JSON syntax |
| `License compliance` | go-licenses allow-list |
| `EditorConfig` | encoding/newline hygiene |
| `OpenSSF Scorecard` | supply-chain posture |
| `Dependency graph` | Go module submission for the dependency graph |

Scheduled-only workflows (`Scheduled fuzzing`, `Stale`) are not required checks.
`Labeler` is advisory.

Optional secret: `SCORECARD_TOKEN` (fine-grained PAT) deepens private-repo
Scorecard checks (branch protection visibility, etc.).

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
Workflow files in `.github/workflows/` implement the automated half of the
control set; they cannot substitute for hosting enforcement.
