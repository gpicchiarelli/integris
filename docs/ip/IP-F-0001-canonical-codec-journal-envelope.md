# IP-F-0001: Canonical codec and journal record envelope

- Status: Draft
- Category: IP-F
- Authors: Integris maintainers
- Reviewers: technical, security, assurance
- Created: 2026-08-01
- Supersedes:
- Requirements: INT-IC2-0001, INT-IC3-0002
- Anchors: `docs/specifications/journal.md`
- Unlocks: `internal/codec`, `internal/journal`, VER-JOURNAL-001, EVD-JOURNAL-001
- Related: provisional digest choice pending IP-C ratification (see Decision § Commitment)

## Motivation

The journal specification defines an append-only, self-delimiting, commitment-
chained log but defers exact binary encoding to an IP-F. Without locked field
widths, endianness, length bounds, and commitment coverage, `internal/codec`
and `internal/journal` cannot produce comparable evidence or an independent
verifier.

## Decision drivers and requirements

- INT-IC2-0001: append-only, versioned, strictly monotonic, cryptographically
  chained, recoverable to the longest complete valid prefix; torn tails reported;
  interior corruption fatal.
- INT-IC3-0002: validate lengths before allocation.
- Independent verifier must share only public format constants and test vectors,
  not writer state machines (`docs/specifications/journal.md`).

## Proposed decision

### Codec principles (`internal/codec`)

1. All multi-byte integers are **little-endian**.
2. Encoding is **canonical**: one bit pattern per abstract value; decoders reject
   non-canonical encodings (e.g. redundant length encodings, trailing junk inside
   a declared payload).
3. Every length and count is checked against explicit maxima **before**
   allocation or copy.
4. No reflection-based codecs on IC-1/IC-2 paths; typed encode/decode only.
5. Errors are typed categories; never panic on hostile or truncated input.

### Journal magic and version

| Field | Value |
|---|---|
| `RecordMagic` | 8 bytes `INTJRN01` (0x49 4E 54 4A 52 4E 30 31) |
| `TrailerMagic` | 8 bytes `INTJRN0T` (0x49 4E 54 4A 52 4E 30 54) |
| `FormatVersion` | `u16` = 1 for this IP |

Unknown `FormatVersion` is fatal for readers that do not explicitly implement it.

### Record envelope layout (format version 1)

Fixed header precedes the payload. `header_length` MUST equal 108 (byte offset
of `payload`); decoders reject any other value for version 1.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `magic` = `RecordMagic` |
| 8 | 2 | `format_version` u16le |
| 10 | 2 | `header_length` u16le (= 108) |
| 12 | 4 | `record_length` u32le (total bytes from `magic` through trailing `record_length`) |
| 16 | 8 | `sequence` u64le (strictly monotonic; first record = 1) |
| 24 | 16 | `transaction_id` opaque |
| 40 | 2 | `record_type` u16le |
| 42 | 2 | `reserved` u16le (= 0; reject nonzero) |
| 44 | 32 | `payload_digest` |
| 76 | 32 | `previous_commitment` |
| 108 | `payload_len` | `payload` |
| 108+payload_len | 32 | `record_commitment` |
| +32 | 8 | `trailer_magic` = `TrailerMagic` |
| +8 | 4 | `record_length` u32le duplicate |

Invariant:

```text
record_length = 108 + payload_len + 32 + 8 + 4
             = 152 + payload_len
```

### Limits (v1)

| Constant | Value |
|---|---|
| `MaxPayloadBytes` | 1 048 576 (1 MiB) |
| `MaxRecordBytes` | 152 + MaxPayloadBytes |
| `MaxJournalSegmentBytes` | 1 073 741 824 (1 GiB) advisory rotation threshold; not a silent truncate |

`record_length` and trailer duplicate must match; both must be ≥ 152 and
≤ `MaxRecordBytes`. `payload_len` derived from `record_length` must not overflow.

### Record types (v1 allow-list)

| Code | Name | Notes |
|---|---|---|
| 1 | `observation` | |
| 2 | `plan_digest` | |
| 3 | `authorization` | |
| 4 | `progress` | |
| 5 | `confirmation` | |
| 6 | `cancellation` | |
| 7 | `quarantine` | |
| 8 | `recovery` | |
| 9 | `checkpoint` | |
| 10 | `evidence_reference` | |

Unknown or zero `record_type` is fatal (non-canonical / unsupported). Payloads
MUST NOT embed file contents, raw keys, secrets, or unnecessary personal data
(enforced by higher-layer validators; codec only bounds bytes).

### Commitment (provisional digest)

**Provisional for M1 kernels:** digests and commitments use **SHA-256**
(32-byte output) as specified by FIPS 180-4.

- `payload_digest = SHA-256(payload)`
- Genesis `previous_commitment` for `sequence == 1` is 32 zero bytes.
- For `sequence > 1`, `previous_commitment` MUST equal the prior record’s
  `record_commitment`.
- `record_commitment = SHA-256(commitment_preimage)` where `commitment_preimage`
  is the concatenation of these fields in order, each in canonical encoding:
  `magic || format_version || header_length || record_length || sequence ||
  transaction_id || record_type || reserved || payload_digest ||
  previous_commitment || payload`.

The `record_commitment`, `trailer_magic`, and trailing `record_length` are
**not** included in the preimage.

**IP-C note (stub, not a full suite):** SHA-256 is locked here only so codec and
journal kernels can ship test vectors. A future IP-C must independently ratify
(or replace) the journal commitment primitive before release evidence that
claims cryptographic strength beyond integrity-under-local-adversary testing.
This IP does not select AEAD, signatures, KDFs, or session suites.

### Append transaction

1. Construct one canonical record in bounded memory; validate all fields.
2. Write to a new segment or append position **without** overwriting committed
   prefix bytes.
3. Persist record bytes per the filesystem publication profile.
4. Persist containing metadata/directory when the profile requires.
5. Only then expose the new sequence as committed to readers.

### Reader acceptance rule

A reader accepts the **longest** fully delimited, canonical, commitment-valid,
strictly monotonic (`sequence` increases by exactly 1) prefix.

| Condition | Behavior |
|---|---|
| Torn / incomplete final record | report torn tail; quarantine tail bytes; accept prior prefix |
| Interior corruption, bad magic, bad commitment, length mismatch | **fatal**; do not skip |
| Sequence gap or fork (`previous_commitment` mismatch) | **fatal** |
| Limit violation | **fatal** for that stream |
| Nonzero `reserved` or wrong `header_length` for version | **fatal** |

### Package split

- `internal/codec`: primitive encoders/decoders and digest helpers used by journal
  and later by plan digests.
- `internal/journal`: append writer, prefix reader, and a separate
  `internal/journal/verify` (or equivalent) read-only verifier sharing only
  constants and vectors.

## Alternatives considered

- **JSON/CBOR journal lines:** rejected for IC-2 recovery; ambiguous canonicality
  and weak self-delimiting truncation behavior under crash.
- **Big-endian network order:** rejected; little-endian matches the restricted Go
  profile’s predominant host targets and simplifies golden vectors on declared
  platforms; one endianness forever for v1.
- **Unsigned varints for all lengths:** deferred; fixed widths reduce decoder
  branches for M1 evidence; a later format version may introduce them via IP.
- **Full IP-C suite before any journal code:** rejected for M1 throughput;
  provisional SHA-256 with explicit IP-C gate is sufficient for structural
  VER-JOURNAL-001 evidence.

## Risk analysis

**Mitigates:** THR-0006 / THR-0008 aspects of journal truncation and tampering
detection; HAZ-0002 / HAZ-0005 / HAZ-0006 as tied to INT-IC2-0001.

**Residual risk:** SHA-256 provisional choice not yet specialist-reviewed;
implementation bugs in length arithmetic; shared constants drift between writer
and verifier (mitigate with single generated constant source and differential
tests).

**Failure behavior:** fail closed on interior errors; never skip gaps; never
overwrite committed bytes.

**Complexity cost:** fixed layout and dual length fields add code but enable
reverse boundary discovery and truncation campaigns.

## Compatibility and portability

Format version 1 is architecture-independent. Segment files are opaque byte
sequences; no host struct packing. Compaction (new journal + linkage proof)
remains a separate authorized transaction per the journal specification and is
out of scope for the initial writer beyond refusing in-place edits.

## Migration strategy

Empty journals initialize with no records (next sequence 1). Changing field
layout requires `FormatVersion >= 2` and a superseding IP-F. Readers must not
guess unknown versions.

## Verification strategy and acceptance criteria

Aligned with `docs/verification-plan.md` and VER-JOURNAL-001:

| Layer | Required work |
|---|---|
| Unit | Golden encode/decode vectors; every field boundary; reserved≠0 reject |
| Property | Random valid records round-trip; commitment chain monotonicity |
| Fuzz | Hostile byte streams against decoder and prefix reader |
| Fault injection | Truncate write at every byte offset; bit flips interior vs tail |
| Differential | Independent verifier vs writer-produced journals |
| Review | Technical + security review of layout and commitment preimage |

**Acceptance (VER-JOURNAL-001 / EVD-JOURNAL-001):**

1. Reader accepts exactly the longest complete valid prefix.
2. Torn final record is reported; interior alteration, gap, fork, non-canonical
   record, or limit violation is rejected without skipping.
3. Evidence under `evidence/journal/` with digests and reviewer
   (EVD-JOURNAL-001 produced).

## Retirement/rollback plan

If IP-C replaces the digest algorithm, publish format version N with dual-read
evidence and forbid silent downgrade of commitment verification. In-place
rewriting of old journals remains prohibited; migrate via compaction transaction.

## Dissent and unresolved questions

1. **IP-C ratification of SHA-256** (or replacement) before cryptographic release
   claims — required; open until IP-C exists.
2. **`transaction_id` entropy/source** — opaque 16 bytes here; allocation rules
   belong to transaction/protocol IPs.
3. **Multi-segment index format** — not specified; M1 may use a single segment
   file plus documented rotation later.
4. **Whether `header_length` should remain fixed-only in v1** — yes in this IP;
   extensible headers deferred to v2 to keep VER-JOURNAL-001 finite.

## Decision and approvals

Draft for M1 review. `internal/codec` and `internal/journal` must not merge as
product kernels until this IP is Accepted (or superseded).

- Technical reviewer:
- Security reviewer:
- Assurance owner:
