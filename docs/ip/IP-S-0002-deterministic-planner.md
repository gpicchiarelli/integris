# IP-S-0002: Deterministic canonical planner

- Status: Draft
- Category: IP-S
- Authors: Integris maintainers
- Reviewers: technical, security, assurance
- Created: 2026-08-01
- Supersedes:
- Requirements: INT-IC2-0002, INT-IC1-0006, INT-IC3-0002
- Anchors: `docs/specifications/filesystem-model.md`, `docs/go-profile.md`
- Depends on: IP-F-0001 (canonical codec and digests for plan bytes)
- Unlocks: `internal/plan`, VER-PLAN-001, EVD-PLAN-001

## Motivation

Authorization binds a plan digest. If planning depends on map iteration,
goroutine schedule, acquisition order, locale, or wall clock, two honest runs
can authorize different byte sequences for the “same” intent, breaking recovery
and enabling subtle integrity failures. M1 needs a deterministic planner kernel
before transaction authorization can be tested.

## Decision drivers and requirements

- INT-IC2-0002: identical initial state, manifest, immutable configuration, and
  capability vector ⇒ byte-identical canonical plans and digests.
- INT-IC1-0006: every relevant semantic classified exactly once; refuse
  `UNREPRESENTABLE` and `UNKNOWN` by default; no silent loss.
- Go profile: sorted keys before serialization, hashing, planning, or
  authorization; no security decisions from map/goroutine/wall-clock order.
- Filesystem model: results canonically sorted by path and capability identifier.

## Proposed decision

### Inputs (canonicalized before planning)

Planning consumes only:

1. **Manifest** — already-canonical object list (paths as IP-S-0001 component
   sequences; content digests; declared source semantics).
2. **Capability vector** — immutable per-session vector from the filesystem
   model (identity, case, Unicode, links, ACL/xattr, times, sync, etc.).
3. **Immutable configuration digest** and the subset of policy fields required
   for classification (destructive thresholds, wrap allow-lists, forbid lists).
4. **Resource limits** — maximum entries, maximum plan bytes, maximum capability
   comparisons (INT-IC3-0002).

Inputs MUST be fully validated and sorted before the planner admits work.
Acquisition order of observations MUST NOT affect outputs: the planner
re-sorts and rehashes from values, never from arrival time.

### Capability classification

For each `(path, capability_id)` relevant to the manifest entry and target
vector, the planner emits exactly one of:

| Result | Meaning | Default authorization effect |
|---|---|---|
| `LOSSLESS` | equivalent semantics | may proceed |
| `WRAPPED` | reversible envelope with accepted format + restoration test | may proceed only if wrap format ID is in policy allow-list |
| `UNREPRESENTABLE` | cannot preserve | **refuse** |
| `POLICY_FORBIDDEN` | possible but prohibited | **refuse** |
| `UNKNOWN` | not reliably characterized | **refuse** |

No configuration default permits silent loss. IC-4 optimization among equivalent
representations is forbidden until equivalence has separate verification evidence;
M1 planner selects the single lexicographically least allowed representation
identifier when multiple `LOSSLESS` encodings are explicitly enumerated by
policy (stable tie-break), otherwise the sole declared mapping.

### Plan document structure (v1)

The canonical plan is a binary document encoded with IP-F-0001 codec primitives
(little-endian, fixed-width integers, explicit lengths). Logical fields in
encode order:

1. `plan_magic` — 8 bytes `INTPLAN1`
2. `plan_version` — u16 = 1
3. `manifest_digest` — 32 bytes (SHA-256 provisional per IP-F-0001)
4. `capability_vector_digest` — 32 bytes
5. `configuration_digest` — 32 bytes
6. `entry_count` — u32
7. `entries` — array, **sorted ascending** by path (component-wise byte order
   per IP-S-0001 components) then by `capability_id` (u16) then by
   `action_code` (u16)
8. Each entry: `path_component_count`, components (length-prefixed),
   `capability_id`, `action_code`, `result_code`, `representation_id`
   (u16; 0 if unused), `aux_digest` (32 bytes; zeros if unused)
9. `destructive_summary_digest` — 32 bytes over the sorted destructive-action
   sublist (may be zeros if none)
10. `plan_body_digest` reserved as the digest of all preceding canonical bytes

`action_code` allow-list (v1): `1=create`, `2=replace`, `3=metadata_update`,
`4=quarantine_delete`, `5=skip_identical`. Unknown codes reject the plan build.

### Determinism rules

The planner MUST NOT read:

- wall clock, timers, or random oracles for decisions;
- unsorted map iteration order;
- goroutine completion order;
- locale, timezone, or floating-point formatting;
- live filesystem state except through the already-captured capability vector
  and manifest (re-probes invalidate the vector and require replan).

Parallel schedules and randomized acquisition of the **same** canonical inputs
MUST yield byte-identical plan bytes and digests (VER-PLAN-001 criterion).

### Failure behavior

| Condition | Effect |
|---|---|
| Any `UNREPRESENTABLE` / `UNKNOWN` / forbidden | no plan bytes authorized; preflight report enumerates each blocking `(path, capability_id, result)` in canonical order |
| Limit exceeded | refuse before allocation; no partial authorize-able artifact |
| Input non-canonical | reject; do not normalize silently |
| Capability vector change after plan | plan invalidated; must replan |

Planning alone performs **no archive mutation**.

### Kernel API shape

`internal/plan`:

- `Build(input CanonicalInput) (Plan, Preflight, error)`
- `Digest(Plan) []byte` using IP-F-0001 digest helper
- pure functions over in-memory inputs; I/O only via injected capability snapshots
  already taken by callers

## Alternatives considered

- **JSON plan with sorted keys only:** weaker canonicality (Unicode escapes,
  key typography); rejected as the sole IC-2 artifact; may exist as a debug dump
  but authorization binds the binary plan digest.
- **Allow silent drop of unknown xattrs:** rejected; violates INT-IC1-0006.
- **Nondeterministic parallel classify-then-merge without sort:** rejected;
  fails VER-PLAN-001 by construction.
- **Embed full capability vector in every plan:** digest binding is enough for
  authorization; full vector remains session state to limit plan size.

## Risk analysis

**Mitigates:** THR-0005 aspects of binding wrong or unstable plans; HAZ-0002 /
HAZ-0005 for INT-IC2-0002.

**Residual risk:** incomplete capability ID taxonomy; policy allow-list errors
marking `WRAPPED` as safe; digest algorithm provisional until IP-C.

**Failure behavior:** refuse closed; structured preflight; no mutation.

**Complexity cost:** explicit sort and stable tie-break rules; required for
authorization soundness.

## Compatibility and portability

Plan digests must match across declared platforms for identical inputs. Tests
include cross-platform golden vectors. Path component ordering uses raw
validated UTF-8 bytes after IP-S-0001 checks, not locale collation.

## Migration strategy

`plan_version` increments via superseding IP. Old digests remain meaningful for
recovery of in-flight transactions; mixed-version authorization is rejected
unless an explicit migration IP allows dual verification.

## Verification strategy and acceptance criteria

Aligned with `docs/verification-plan.md` and VER-PLAN-001:

| Layer | Required work |
|---|---|
| Unit | Golden plans for fixed inputs; every result_code path; limit boundaries |
| Property | Randomized permutation of input acquisition; map order perturbation |
| Differential | Parallel schedules; cross-platform golden digests |
| Negative | Unknown capability, non-NFC path (rejected earlier), silent-loss attempts |
| Review | Technical review of sort keys and tie-break |

**Acceptance (VER-PLAN-001 / EVD-PLAN-001):**

1. All permutations and schedules of identical canonical inputs produce
   byte-identical plan output and digest.
2. Blocking classifications never yield an authorize-able plan.
3. Evidence under `evidence/planner/` with digests and reviewer
   (EVD-PLAN-001 produced).

## Retirement/rollback plan

If determinism is broken by a language/runtime change, freeze the toolchain
(Go profile IP) before shipping planner changes. A non-deterministic build
cannot produce EVD-PLAN-001 release evidence.

## Dissent and unresolved questions

1. **Complete capability_id registry** — filesystem-model lists themes; numeric
   registry may grow with VER-FS-001 without changing plan_version if new IDs
   are additive and unknown IDs refuse closed.
2. **Destructive summary schema** — digest input layout needs a short follow-up
   when deletion IP details land; until then summary digest is SHA-256 of the
   sorted canonical destructive entry subset defined in this plan version.
3. **Whether debug JSON is in-tree** — optional; must not be used for
   authorization.

## Decision and approvals

Draft for M1 review. `internal/plan` must not merge until this IP is Accepted
(or superseded) and IP-F-0001 digest helpers are available.

- Technical reviewer:
- Security reviewer:
- Assurance owner:
