# IP-S-0001: Path name grammar and descriptor-relative resolution

- Status: Draft
- Category: IP-S
- Authors: Integris maintainers
- Reviewers: technical, security, assurance
- Created: 2026-08-01
- Supersedes:
- Requirements: INT-IC1-0002, INT-IC3-0002
- Anchors: `docs/specifications/path-resolution.md`
- Unlocks: `internal/path`, VER-PATH-001, EVD-PATH-001

## Motivation

String sanitation, `filepath.Clean`, and prefix checks do not prevent symlink
substitution, mount crossings, or platform-specific reserved-name traps. M1
needs a single rejectable grammar and a descriptor-relative resolution algorithm
before any archive mutation kernel can claim root containment.

## Decision drivers and requirements

- INT-IC1-0002 requires mutation only through an already-open authorized root
  descriptor and a verified descriptor chain, without following symbolic links
  or crossing unauthorized mounts/volumes.
- INT-IC3-0002 requires every externally influenced length and count to be
  bounded before allocation or syscall use.
- `docs/specifications/path-resolution.md` already states the safety properties;
  this IP locks encoding, limits, reject tables, post-open checks, and failure
  behavior so `internal/path` can be implemented without further format debate.

## Proposed decision

### Name grammar (protocol path)

A protocol path is a non-empty sequence of one or more **canonical name
components**. Components are opaque UTF-8 byte strings after validation; the
kernel never invents separators or re-parses a joined string for authorization.

A component is **rejected** if any of the following hold:

| Rule ID | Condition |
|---|---|
| G-EMPTY | empty byte sequence |
| G-DOT | exactly `.` |
| G-DOTDOT | exactly `..` |
| G-NUL | contains `U+0000` |
| G-SEP | contains `/` (0x2F) or `\` (0x5C) |
| G-ABS | equals a platform absolute indicator (leading `/`, drive/`\\` forms) when presented as a single component, or any absolute path form when a joined string is offered to the API |
| G-UTF8 | not well-formed UTF-8 (overlong encodings, surrogates, truncated sequences) |
| G-NORM | Unicode scalar sequence is not NFC (reject; do not silently normalize) |
| G-CTRL | contains C0 controls other than TAB (TAB also rejected) or DEL |
| G-LEN | length in bytes exceeds `MaxComponentBytes` |
| G-COUNT | path component count exceeds `MaxComponents` |
| G-BUDGET | sum of component byte lengths exceeds `MaxPathBytes` |
| G-WINRES | on profiles that declare Windows-hostile name rules: case-folded match to `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, optionally with a trailing extension; also names ending in `.` or space |
| G-UNK | violates a profile-declared reserved-name or encoding rule not listed above |

Default M1 limits (immutable constants for format/profile version 1):

| Constant | Value | Rationale |
|---|---|---|
| `MaxComponentBytes` | 255 | common POSIX `NAME_MAX` ceiling; rejects before syscall |
| `MaxComponents` | 1024 | finite planning and recursion bound |
| `MaxPathBytes` | 4096 | sum of component bytes only (no separators counted in the budget) |

String validation **does not authorize access**. A validated path is only an
input to descriptor-relative resolution under a conferred root.

### Resolution algorithm

1. Receive an already-open, policy-authorized root directory descriptor and its
   captured volume/filesystem identity (`RootIdentity`).
2. Validate the entire component sequence against the grammar before any open.
3. For each canonical component, open relative to the held parent descriptor with
   **no-follow** semantics and the minimum required rights. Never resolve via a
   process-wide working directory or absolute path reconstructed from strings.
4. After each open, verify object type, identity (inode/file-id as available),
   link-count constraints required by the plan, mount/volume identity continuity
   against `RootIdentity` (and any explicitly authorized mount set), and expected
   metadata. Failure aborts the chain and closes intermediate descriptors.
5. Retain descriptors through mutation; never re-resolve an authorized string.
6. For creation: validate the parent chain; create a unique staged name with
   exclusive create semantics; validate the created object; publish only per the
   transaction specification (out of scope for this IP’s mutation steps).
7. Refuse symbolic links, unauthorized mount crossings, detectable identity
   changes between check and use, unavailable required primitives, and unknown
   platform semantics. Hard links are policy-controlled; special files are
   prohibited by default.

### Kernel API shape (normative for M1)

`internal/path` exposes:

- pure `ValidateComponents([][]byte) error` with stable reject rule IDs;
- `Resolve(root Dir, components [][]byte, opts ResolveOpts) (Chain, error)` where
  all filesystem operations go through an injectable `Dir`/`File` interface so
  unit and race harnesses need no real FS;
- post-open fact accessors (type, identity, volume id) rather than path strings.

Platform adapters must return post-open facts. Emulating security with
`filepath.Clean`, lexical join, or prefix string comparison is non-conformant.

### Failure behavior

| Failure | Archive effect | Caller observation |
|---|---|---|
| Grammar reject | none | typed error with rule ID; no syscall for that component |
| Open/no-follow failure | none | typed error; partial chain closed |
| Post-open identity/type/volume mismatch | none | typed error; treat as race/substitution |
| Symlink encountered | none | reject (G-LINK / resolution policy) |
| Unauthorized mount/volume change | none | reject |
| Limit overflow | none | reject before allocation |

Resolution failure has **no archive mutation effect**. Errors never panic for
expected input or FS faults (Go profile).

## Alternatives considered

- **Lexical clean + prefix check:** rejected; TOCTOU and symlink races remain.
- **Silent Unicode normalization:** rejected; changes identity of names and hides
  peer/platform disagreement; reject non-NFC instead.
- **Unlimited component size “like the OS”:** rejected; violates INT-IC3-0002 and
  makes fuzzing/resource evidence unbounded.
- **Follow symlinks inside the root:** rejected; violates INT-IC1-0002 and the
  path-resolution specification.
- **Windows-only short-name (8.3) acceptance:** rejected for M1; treat as
  profile-unknown/forbidden until an accepted platform profile defines evidence.

## Risk analysis

**Mitigates:** THR-0001 (path traversal / root escape), THR-0002 (symlink and
mount substitution), HAZ-0001 / HAZ-0007 as controlled by INT-IC1-0002.

**Residual risk:** kernel bugs in no-follow/openat; incomplete volume-identity
APIs on some platforms; hard-link aliases under permissive policy; adapter
incorrectly reporting post-open facts.

**Failure behavior:** fail closed; no mutation; no ambient path re-resolution.

**Common-cause risk:** shared mistaken adapter helpers; mitigate with per-platform
negative tests and independent review of adapters.

**Complexity cost:** injectable FS and post-open checks add harness surface;
required for VER-PATH-001 evidence.

**Assumptions:** launcher confers a correct root descriptor and expected volume
identity; M2 privilege separation (IP-A-0001) will further confine who may hold
that descriptor.

## Compatibility and portability

Grammar and limits are protocol/profile constants, identical on all Go ports.
Platform differences appear only in adapters (how no-follow and volume identity
are obtained). A platform that cannot provide required post-open facts or
no-follow opens cannot claim INT-IC1-0002 conformance and must refuse product
mutation paths.

## Migration strategy

No on-disk product format yet. Accepting this IP unblocks `internal/path`.
Changing limits or NFC policy later requires a superseding IP and dual-corpus
tests; lowering reject strictness is an IC-1 change.

## Verification strategy and acceptance criteria

Aligned with `docs/verification-plan.md` layers and VER-PATH-001:

| Layer | Required work |
|---|---|
| Unit | Exhaustive reject-table tests for every G-\* rule; boundary lengths 0, 1, 255, 256; NFC vs NFD twins; overlong UTF-8 |
| Property / generative | Arbitrary component sequences under budget; shrinking to minimal reject |
| Fuzz | Continuous fuzz on component bytes and component counts |
| Integration | Symlink, hard-link, and mount-race harnesses; post-open identity substitution; real FS on each declared platform |
| Review | Independent security review of grammar + adapters |

**Acceptance (maps to VER-PATH-001 / EVD-PATH-001):**

1. No invalid component, race, link, identity change, or unauthorized mount causes
   filesystem access outside the conferred root.
2. No grammar or resolution failure produces archive mutation.
3. Evidence package under `evidence/path/` records revision, platform, corpus,
   commands, digests, and reviewer (EVD-PATH-001 produced, not merely planned).
4. Coverage percentage alone is not acceptance.

## Retirement/rollback plan

If a platform cannot meet no-follow + post-open identity requirements, withhold
support for that platform’s apply path rather than weaken the grammar. A
development-only mock FS may be used for unit tests but cannot produce release
evidence for VER-PATH-001 platform rows.

## Dissent and unresolved questions

1. **Exact volume-identity tuple per OS** (device id, FS UUID, mount generation)
   needs platform-adapter IPs or matrix rows before M2; M1 injectable tests may
   use abstract identity equality.
2. **Hard-link default policy** (forbid vs allow-with-plan) is left to session
   policy; this IP only requires policy to be explicit and checked post-open.
3. **Whether TAB in names should ever be allowed** — currently rejected; reopen
   only with an interoperability need and a superseding IP.

## Decision and approvals

Draft for M1 review. Product path kernel code must not merge until this IP is
Accepted (or superseded) and reviewers required by INT-IC1-0002 have signed off.
Status remains Draft until technical, security, and assurance approvals are
recorded below.

- Technical reviewer:
- Security reviewer:
- Assurance owner:
