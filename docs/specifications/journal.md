# Verifiable journal specification

Status: **Pre-implementation format constraints**
Criticality: IC-1/IC-2

The journal is an append-only transaction/evidence log, not a general database.
The filesystem remains authoritative for content.

## Record envelope

```text
magic | format_version | header_length | record_length | sequence |
transaction_id | record_type | payload_digest | previous_commitment |
payload | record_commitment | trailer_magic | record_length
```

The exact canonical binary encoding and cryptographic suite require accepted
IP-F/IP-C proposals. Every length is bounded and validated before allocation.
The duplicated length and trailer allow reverse boundary discovery; commitment
binds every canonical header field, payload, and previous commitment.

## Allowed payload classes

Observation, plan digest, authorization, progress, confirmation, cancellation,
quarantine, recovery, checkpoint, and evidence reference. Records do not embed
file contents, keys, secrets, or unnecessary personal data.

## Append transaction

1. construct and validate one canonical record in bounded memory;
2. write to a new segment or append position without overwriting committed bytes;
3. persist record bytes according to the filesystem profile;
4. persist containing metadata/directory when required;
5. only then expose the sequence as committed.

A reader accepts the longest fully delimited, canonical, commitment-valid,
strictly monotonic prefix. A torn final record is reported and quarantined; any
interior corruption, sequence gap, fork, or commitment mismatch is fatal and
cannot be skipped.

## Recovery, checkpoints, compaction

Recovery is deterministic and idempotent from an accepted prefix plus filesystem
observations. Checkpoints commit the complete prior head, state digest, format,
and compaction policy. Compaction is a separate authorized transaction that
produces a new journal and signed linkage proof; it never edits the old journal
in place. An independent read-only verifier shares no writer code except public
format constants and test vectors.
