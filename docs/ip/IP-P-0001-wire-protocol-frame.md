# IP-P-0001: Wire protocol frame widths and byte order

- Status: Draft
- Category: IP-P
- Authors: Integris maintainers
- Reviewers: technical, security, cryptography, assurance
- Created: 2026-08-01
- Supersedes:
- Requirements: INT-IC1-0003, INT-IC3-0002
- Anchors: `docs/specifications/protocol.md`, `formal/session/Session.tla`,
  `internal/session`
- Depends on: IP-C-0001 (hashing); session AEAD suite still deferred
- Unlocks: interoperable network frame codec (future `internal/protocol`)

## Motivation

`protocol.md` deferred integer widths and byte order to an IP-P. M1 session
logic exists without a wire codec. Locking the frame skeleton now unblocks an
implementation without inventing crypto.

## Decision drivers and requirements

- Self-delimiting frames; lengths validated before allocation.
- One canonical encoding; reject non-minimal / unknown critical fields.
- Session state machine in `internal/session` / Session.tla remains authoritative
  for sequencing of auth/activate; this IP only fixes bytes on the wire.

## Proposed decision

### Byte order and integers

All multi-byte integers are **little-endian** unsigned (`u8`/`u16`/`u32`/`u64`).

### Frame v0 (engineering preview)

```text
magic[8] = "INTPRO01"
protocol_version u16 = 1
message_type u16
flags u16
body_length u32
session_id[16]
sequence u64
body[body_length]
authenticator[32]   # provisional HMAC-SHA256 per IP-C-0001 when keyed;
                    # zeros forbidden when policy requires auth
```

Header size before body: `8+2+2+2+4+16+8 = 42` bytes.

### Limits (profile v1)

| Limit | Value |
|---|---|
| Max body length | 1 MiB |
| Max frames per session | implementation policy ≥ Session.MaxMessages for control plane |
| Max concurrent sessions | configuration (`session` resource limits) |

### Message type allow-list (initial)

| Code | Name | Critical if unknown |
|---|---|---|
| 1 | NegotiateOffer | yes |
| 2 | NegotiateAccept | yes |
| 3 | PeerAuth | yes |
| 4 | ArchiveAuth | yes |
| 5 | Activate | yes |
| 6 | Data | no (ignored only if flag permits; default reject) |
| 7 | Close | yes |
| 8 | Failure | yes |

Unknown critical types → FAIL session (matches Session.tla FAILED).

### Flags

Bit0 `REQUIRES_MAC` — authenticator must verify.  
Bits 1–15 reserved MBZ.

## Alternatives considered

- **Big-endian / protobuf:** rejected for M1 consistency with journal/IPC LE.
- **Full Noise/TLS framing now:** deferred to superseding IP-C + IP-P.

## Risk analysis

Without AEAD, frames are malleable on path; acceptable only for offline test
vectors and loopback until IP-C session suite lands. Downgrade resistance
depends on transcript binding once crypto exists.

## Verification strategy and acceptance criteria

- Golden encode/decode vectors for empty and max body.
- Session conformance: Negotiate→…→Activate using decoded frames.
- Fuzz decoder; never allocate from unauthenticated length beyond Max.
- EVD-PROTO-001 remains planned until crypto review + MAC-required policy.

## Retirement/rollback plan

Bump `protocol_version` and magic; dual-stack during M3 preview.

## Dissent and unresolved questions

- Exact authenticator: HMAC vs AEAD tag placement.
- Whether `session_id` is public random or derived.
- Data plane multiplexing vs separate content channel.

## Decision and approvals

Draft — no `internal/protocol` package yet; session state is independent.
Approvals open.
