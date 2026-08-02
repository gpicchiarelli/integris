# Protocol baseline

Status: **Pre-implementation, version 0; not interoperable**
Criticality: IC-1/IC-2

**Normative expansion:** [replication-protocol.md](replication-protocol.md)
(INT-PROTO-0001) is the authoritative behavioural contract for session,
handshake, replication cycle, atomicity, recovery, conflicts, integrity,
journal obligations, retry/timeout policy, invariants, failure matrix, and
threat analysis. This file remains the concise wire/session baseline; on
conflict of detail, INT-PROTO-0001 prevails for semantics, and accepted IP-P /
IP-C documents prevail for frozen bit layouts.

## Frame

Every binary frame is canonical and self-delimiting:

```text
magic | protocol_version | message_type | flags | body_length |
session_id | sequence | body | authenticator
```

Integer widths and byte order are fixed by the future IP-P format. Every field,
message, collection, nesting depth, and session total has a normative maximum.
Lengths are validated before allocation. There is one encoding for each value;
non-minimal, duplicate, out-of-order, trailing, or unknown critical data is
rejected. No decoder structure directly triggers filesystem activity.

## Session sequence

`NEW → NEGOTIATING → PEER_AUTHENTICATED → ARCHIVE_AUTHORIZED → ACTIVE → CLOSING → CLOSED`

INT-PROTO-0001 expands intermediate authentication/resume states
(`NEGOTIATED`, `PEER_AUTHENTICATING`, `ARCHIVE_AUTHORIZING`, `ACTIVATING`,
`RESUMING`) while preserving this observable spine. Formal model
`Session.tla` abstracts negotiation as `NEGOTIATED` and omits `CLOSING` /
`RESUMING`.

Any authentication, sequence, canonicalization, quota, downgrade, archive,
timeout, or peer-role failure enters `FAILED`, erases session secrets, closes
transport, and records a stable redacted cause.

## Authentication and negotiation

Peers mutually authenticate. The transcript binds protocol version, exact
algorithm suite, both node identities and roles, archive identity, nonces,
ephemeral keys, limits, and capability digests. The selected version is the
highest mutually allowed version under both local minimum-version policies;
offered sets and selection are transcript-bound. The peer cannot nominate an
arbitrary algorithm. There is no unauthenticated fallback.

## Replay and ordering

Session IDs are unpredictable and unique within the key lifetime. Each direction
has an independent monotonic sequence space and authentication key. Duplicate,
skipped where not explicitly allowed, wrapped, cross-direction, cross-session,
or cross-message-type authenticators are rejected. Resume uses a fresh handshake
that binds the previous authenticated checkpoint and new session identity.

## Flow control and shutdown

Credits bound bytes, frames, work, and buffered content. Credit violations close
the session. Cancellation is explicit, authenticated, and idempotent. Graceful
close confirms the final accepted sequence and transaction/checkpoint state;
transport EOF is interruption, never successful completion.

## Error policy

Wire errors have stable code, fatality, retry class, and safe redacted context.
Security-sensitive details remain local. Unknown error classes are fatal. Retry
never reuses session nonces or bypasses authorization.
