# IP-S-0003: Idempotent crash recovery kernel

- Status: Draft
- Category: IP-S
- Authors: Integris maintainers
- Reviewers: technical, security, assurance
- Created: 2026-08-01
- Supersedes:
- Requirements: INT-IC2-0003, INT-IC1-0004
- Anchors: `docs/specifications/transaction.md`, `docs/specifications/journal.md`,
  `formal/transaction/Transaction.tla`
- Depends on: IP-F-0001 (journal prefix), IP-S-0002 (plan digest binding)
- Unlocks: `internal/recovery`, VER-RECOVERY-001, EVD-RECOVERY-001
  (partial contribution to VER-TXN-001)

## Motivation

Power loss and process kill are expected. Recovery must preserve authorization
and journal-prefix invariants, must not duplicate publication or confirmation,
and must converge under repetition. Without an explicit crash-point catalog and
idempotent rules, fault-injection evidence cannot map to the TLA+ model.

## Decision drivers and requirements

- INT-IC2-0003: after interruption at any identified persistence point, recovery
  preserves authorization and valid-prefix invariants; no duplicate
  publication/confirmation; repeated recovery is effect-free at the stable state.
- INT-IC1-0004: publication unreachable without exact authorization bindings;
  recovery must not invent authorization.
- Transaction specification publication invariants and formal model invariants:
  `PublicationAuthorized`, `PublicationPrepared`, `ConfirmationUnique`,
  `NoInventedPublication`.
- Verification plan crash campaign: kill before/after each meaningful write,
  sync, rename, directory sync, journal append, and publication boundary.

## Proposed decision

### Recovery inputs

Recovery consumes only:

1. Longest valid journal prefix (IP-F-0001 reader); torn tail reported and
   quarantined, never skipped interiors.
2. Observed filesystem state under the conferred archive root (IP-S-0001
   resolution), including staging and publication sentinels defined by the
   platform publication profile.
3. Immutable session identity bindings already recorded in the journal
   (transaction id, plan digest, authorization digest, root/volume identity).

Recovery **MUST NOT** widen authority, mint authorization, follow new peer
input, or treat ambient path strings as authoritative.

### State reconstruction

Map journal + observations to the transaction state set in
`formal/transaction/Transaction.tla` and `docs/specifications/transaction.md`:

```text
CREATED → AUTHENTICATED → MANIFEST_VERIFIED → PLANNED → AUTHORIZED →
CONTENT_RECEIVED → PREPARED → VERIFIED → PUBLISHING → PUBLISHED → CONFIRMED
```

Side states: `SUSPENDED`, `CANCELLED`, `QUARANTINED`, `RECOVERING`,
`IRRECOVERABLE`.

Rules:

1. Enter `RECOVERING` on startup when a non-terminal transaction prefix exists
   without a durable confirmation, or when a torn tail / incomplete publication
   sentinel is observed.
2. If observations prove publication linearization completed **and** journal
   contains a valid preparation + authorization chain consistent with the
   published content, reconstruct `PUBLISHED` (or `CONFIRMED` if confirmation
   record exists). Never confirm without publication evidence.
3. If publication did not linearize, remove or quarantine staging only as the
   publication profile allows; land in `QUARANTINED` or `CANCELLED` per recorded
   cancellation/progress records — **not** invent `PUBLISHED`.
4. Unexpected state/record pairs → `QUARANTINED` (or `IRRECOVERABLE` when
   evidence shows contradictory durable effects); never guess a success edge.
5. `IRRECOVERABLE` preserves evidence and requires explicit operator action; it
   MUST NOT be reported as success.

### Idempotence

| Action | Idempotence rule |
|---|---|
| Re-read journal prefix | same accepted prefix and torn-tail report |
| Re-run recovery | second run: no additional journal records required for stability; no second confirmation; no second publication side effect |
| Staging cleanup | existence-tolerant deletes/quarantine moves |
| Confirmation | at most once; if confirmation record present, remain `CONFIRMED` |

These refine the model actions `Recover` / `RecoverAgain`: after the first
successful recovery decision, further recovery leaves the stable state unchanged.

### Crash-point catalog (mandatory harness labels)

Every persistence boundary exposed by journal append and publication profiles
MUST carry a fault-injection label. Minimum M1 set:

| Label | Boundary |
|---|---|
| `J-APPEND-PRE` | before writing any bytes of a new record |
| `J-APPEND-MID` | after partial record bytes, before full `record_length` durable |
| `J-APPEND-POST` | after record bytes durable, before directory/metadata persist |
| `J-META-POST` | after metadata/directory persist exposes the record |
| `P-STAGE-CREATE` | before/after exclusive staged object create |
| `P-STAGE-SYNC` | before/after staged file sync |
| `P-PUBLISH-RENAME` | before/after publication rename/link |
| `P-PUBLISH-DIRSYNC` | before/after directory sync of publication |
| `P-CONFIRM-PRE` | before confirmation journal record |
| `P-CONFIRM-POST` | after confirmation record committed |

Exact platform fsync/rename sequences live in publication profiles; this IP
requires each profile to cite these labels so VER-RECOVERY-001 can enumerate
them.

M1 engineering harness: `journal.CrashSegment` FailAt on `FileSegment` covers
`J-APPEND-PRE` / `J-APPEND-MID` / `J-APPEND-POST` / `J-META-POST` with
`recovery.Recover` round-trip. Recovery-side `PersistIO` FailAt on `FilePersist`
covers `P-STAGE-CREATE` / `P-STAGE-SYNC` / `P-PUBLISH-RENAME` /
`P-PUBLISH-DIRSYNC` / `P-CONFIRM-PRE` / `P-CONFIRM-POST` (cleanup / quarantine /
confirm side effects during Recover). Apply-side `FilePublisher` covers the
stage→sync→rename→dirsync publication profile with the same P-STAGE/P-PUBLISH
labels and derives `FSObservation` for Recover (not a shared PersistIO adapter).
OS SIGKILL at those apply labels is exercised by `cmd/integris-crash-stub`
(`FilePublisher.KillAt` + `launcher.RunEngineering`). Injected FailAt and SIGKILL
are not power-fail / unflushed-page simulation.

### Failure behavior

| Situation | Behavior |
|---|---|
| Interior journal corruption | fatal prefix reject; no product mutation; preserve evidence |
| Torn tail | accept prior prefix; quarantine tail; recover from prefix |
| Missing authorization in prefix | cannot publish; quarantine/cancel staging |
| Partial publish without linearization | no confirmation; restore/quarantine per profile |
| Partial publish with linearization | complete toward `PUBLISHED`/`CONFIRMED` without duplicating effects |
| Authority mismatch (root/volume) | stop; `QUARANTINED` / `IRRECOVERABLE`; no widening |

### Kernel API shape

`internal/recovery`:

- `Recover(JournalPrefix, FSObservation, Policy) (Outcome, error)`
- `Outcome` includes reconstructed state, actions performed (for harness
  accounting), and whether a second call must be a no-op
- injected I/O and crash points for deterministic fault tests (Go profile)

No network peer interaction inside the recovery kernel.

## Alternatives considered

- **Always wipe staging on any crash:** rejected; can destroy recoverable
  verified content after linearization and violates profile-specific
  publish guarantees.
- **Always treat rename as confirmed:** rejected; confirmation is a distinct
  at-most-once journal event in the formal model.
- **Skip interior journal gaps if CRC matches later:** rejected; violates
  INT-IC2-0001 / IP-F-0001.
- **Recovery invents AUTHORIZED from local config alone:** rejected; violates
  INT-IC1-0004.

## Risk analysis

**Mitigates:** THR-0008 (crash inconsistency), HAZ-0001 / HAZ-0002 / HAZ-0006
for INT-IC2-0003.

**Residual risk:** incomplete crash-label coverage on a platform adapter;
mis-specified publication linearization point; observation TOCTOU (mitigate with
descriptor-relative checks and re-validation).

**Failure behavior:** quarantine/irrecoverable rather than invented success;
idempotent re-entry.

**Common-cause risk:** shared mistaken “success” heuristics between apply and
recovery; mitigate with independent state verifier in evidence harness.

**Complexity cost:** large fault matrix; required by verification plan IC-2
minimums.

## Compatibility and portability

Recovery logic is platform-neutral; publication profiles supply linearization
and sync sequences. A profile that cannot name crash labels or durability
behavior cannot claim VER-RECOVERY-001 on that platform.

## Migration strategy

Model-conformance tests pin abstract states to journal record sequences. Evolving
the TLA+ model requires updating this IP’s mapping table and re-running
VER-RECOVERY-001 / VER-TXN-001 suites. No silent broadening of recovery power.

## Verification strategy and acceptance criteria

Aligned with `docs/verification-plan.md`, VER-RECOVERY-001, and formal README
invariants:

| Layer | Required work |
|---|---|
| Model | TLC on `formal/transaction` remains green; document abstraction gaps |
| Unit | State/record pair tables; idempotent double recovery |
| Fault injection | Kill at every catalog label; power-fail simulation where available |
| Integration | Independent verifier: no unauthorized publication; prefix validity; ≤1 confirmation |
| System | Restart loops; disk-full during append/publish |
| Review | Security + assurance review of crash catalog completeness |

**Acceptance (VER-RECOVERY-001 / EVD-RECOVERY-001):**

1. Every injected interruption preserves authorization and valid-prefix
   invariants.
2. Recovery never duplicates publication or confirmation.
3. A second recovery has no additional effect at the stable state.
4. Evidence under `evidence/recovery/` with digests and reviewer
   (EVD-RECOVERY-001 produced).

Partial VER-TXN-001 contribution: illegal transitions and unbound field
mutations discovered during recovery reconstruction prevent publication without
archive side effects.

## Retirement/rollback plan

If a platform cannot support the required persistence barriers, withhold
publication support rather than weaken idempotence. Development-only volatile
stores cannot produce release recovery evidence.

## Dissent and unresolved questions

1. **Full publication profile documents per filesystem** — required before
   platform rows of EVD-RECOVERY-001; M1 may evidence an injected fake profile
   plus one real FS.
2. **SUSPENDED vs QUARANTINED operator UX** — operational IP later; kernel only
   requires distinct states and journal records.
3. **Compaction during recovery** — forbidden in M1; compaction remains a
   separate authorized transaction (journal specification).
4. **Model gap:** TLA+ uses abstract flags; conformance tests must document how
   journal record sequences refine `authorized` / `published` / 
   `confirmationCount` without claiming TLC proves the Go code.

## Decision and approvals

Draft for M1 review. `internal/recovery` must not merge until this IP is
Accepted (or superseded) and dependent journal/plan IPs are Accepted for the
same milestone merge gate.

- Technical reviewer:
- Security reviewer:
- Assurance owner:
