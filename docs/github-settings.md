# Required GitHub repository settings

Repository files cannot fully enforce hosting settings. Before accepting
contributions, an administrator records screenshots/API evidence that `main`
has the controls below.

## Branch protection (`main`)

Target posture:

- deletion and force-push disabled;
- linear history (squash-only merge queue aligns with this);
- all conversations resolved before merge;
- required status checks (strict: branch up to date);
- administrators subject to status checks (`enforce_admins`);
- pull-request reviews: dismiss stale approvals;
- **Require review from Code Owners** once at least one independent reviewer
  account is listed in `.github/CODEOWNERS` (sole-maintainer phase keeps this
  off so the author is not permanently deadlocked; CODEOWNERS still
  auto-requests reviews);
- IC-1 changes still require two independent human approvers per
  `GOVERNANCE.md` even when GitHub review count is zero.

## CODEOWNERS

`.github/CODEOWNERS` assigns `@gpicchiarelli` across assurance, security-sensitive
kernels, hosting automation, and legal/project identity paths.

Rules:

- only real GitHub users/teams;
- never invent placeholder reviewer identities;
- when independent technical / security / assurance reviewers exist, add them to
  the matching paths and turn on required code-owner review.

## Security and automation features

Enable and keep enabled:

- secret scanning and push protection;
- Dependabot security updates and alerts (when the plan exposes them);
- private vulnerability reporting (Security advisories);
- dependency graph;
- Actions enabled with **SHA pinning required** for third-party actions;
- squash-only merges; delete head branch on merge; allow auto-merge;
- allow “update branch” on PRs;
- web commit sign-off required;
- issues on; wiki / projects / downloads off; discussions off (use issues/PRs).

## Required status checks

Make these required on `main` as they remain stable greens:

| Workflow / job | Role |
|---|---|
| `CI` / Verify assurance baseline | fmt, verify, race, govulncheck, profile guards, man-lint |
| `CI` / Bootstrap test (ubuntu + macOS) | cross-host unit tests |
| `CI` / macOS Seatbelt (cgo) | Darwin confinement adapter |
| `CI` / Cross-compile (declared GOOS/GOARCH) | build smoke for Linux/Darwin/FreeBSD/OpenBSD |
| `CI` / Short fuzz | hostile-input kernels |
| `CI` / Coverage profile | structural coverage artifact |
| `Formal models` | TLA+ TLC |
| `CodeQL` / Analyze (go) | semantic code scanning |
| `Dependency review` | PR dependency/license gate |
| `Static analyzers` | staticcheck + gosec |
| `OSV Scanner` | OSV database |
| `SBOM` | CycloneDX / Syft inventories |
| `Secret scanning` / gitleaks | secret hygiene |
| `Workflow lint` / actionlint | workflow correctness |
| `Filesystem vulnerability scan` | Trivy |
| `Semgrep` | OSS rule packs |
| `Typos` / Spell check | identifier/docs spelling |
| `Link check` | Markdown link integrity |
| `FreeBSD` | native FreeBSD tests |
| `OpenBSD` | native OpenBSD tests (M4y) |
| `Reproducible builds` | dual-runner digest equality |
| `Evidence` | campaign/digest regeneration |
| `License compliance` / go-licenses check | license allow-list |
| `EditorConfig` | encoding/newline hygiene |
| `OpenSSF Scorecard` | supply-chain posture |
| `Dependency graph` | Go module submission |

Scheduled-only workflows (`Scheduled fuzzing`, `Stale`) are not required checks.
`Labeler` is advisory.

Optional secret: `SCORECARD_TOKEN` (fine-grained PAT) deepens Scorecard checks.

## Evidence snapshot (2026-08-01, evening)

Probed with `gh` as repository admin on public `gpicchiarelli/integris`.

| Control | Observed | Notes |
|---|---|---|
| Visibility | public | Confirmed via repo API |
| Default branch | `main` | Confirmed |
| Branch protection on `main` | **Enabled** | force-push/delete blocked; linear history; conversation resolution; `enforce_admins` for checks |
| Required status checks | **Core + supply-chain set** | Verify/bootstrap/Seatbelt/cross-compile/fuzz, Formal, CodeQL, analyzers, Trivy, Semgrep, SBOM, lychee, gitleaks, licenses, typos, editorconfig, actionlint; FreeBSD/Scorecard/repro digests stay advisory until stable greens |
| Required PR approval count | 0 (temporary) | Sole-maintainer deadlock avoidance; process still requires independent IC-1 approvers |
| Require code-owner reviews | **Off (temporary)** | CODEOWNERS present and auto-requests; enable when a second owner exists |
| `CODEOWNERS` | **Present** | `.github/CODEOWNERS` → `@gpicchiarelli` |
| Secret scanning + push protection | **Enabled** | Confirmed |
| Dependabot security updates + alerts | **Enabled** | Confirmed |
| Actions SHA pinning required | **Enabled** | Confirmed |
| Auto-merge / update branch | **Enabled** | Squash-only; delete head branch on merge |
| Web commit sign-off | **Required** | Confirmed |
| Wiki / projects / downloads / discussions | **Off** | Issues remain on |
| Private vulnerability reporting | **Enabled** | Confirmed via API |
| Non-provider secret patterns / validity checks | Disabled | Not exposed for this account/plan via API |

**Residual process gap:** independent technical, security, and assurance reviewers
are still unassigned (`GOVERNANCE.md`). Hosting automation cannot invent them.
