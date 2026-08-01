# IP-A-0002: Bounded local IPC frame codec

- Status: Draft
- Category: IP-A
- Authors: Integris maintainers
- Reviewers: technical, security, assurance
- Created: 2026-08-01
- Supersedes:
- Requirements: INT-IC1-0001, INT-IC3-0002
- Anchors: `docs/security-architecture.md` (Local IPC contract)
- Unlocks: `internal/ipc`, M2 process wiring

## Motivation

Privilege-separated processes need a single, fail-closed local channel contract
before M2 spawns real subprocesses. Ad-hoc pipes without role, sequence, and
size bounds recreate confused-deputy and resource-exhaustion hazards inside the
host.

## Decision drivers and requirements

- Every channel has fixed peer roles, protocol version, session nonce, monotonic
  sequence, maximum frame/queue size, and explicit close.
- Unknown critical messages, duplicate sequences, quota exhaustion, role
  mismatch, or authentication failure close the channel.
- INT-IC3-0002: validate lengths before allocation.
- Package boundaries are not security boundaries; IPC authentication is not a
  substitute for OS isolation (IP-A-0001).

## Proposed decision

### Frame layout v1 (`INTIPC01`)

Little-endian canonical encoding:

| Field | Size | Notes |
|---|---|---|
| magic | 8 | `INTIPC01` |
| version | u16 | `1` |
| type | u16 | request/response/close/critical |
| session_nonce | 16 | fixed for channel lifetime |
| sequence | u64 | strictly monotonic from 1 |
| sender_role | u16 | authority role code 1–9 |
| receiver_role | u16 | authority role code 1–9 |
| payload_length | u32 | checked before payload copy |
| payload | N | opaque; AEAD/MAC deferred to IP-C |

Defaults: `MaxFrameBytes = 1 MiB`, `MaxQueueDepth = 1024`.

### Failure behavior

Any role/nonce/sequence/limit/critical failure sets `Closed` and returns a typed
error with `Close=true`. Callers MUST tear down the OS channel.

### Authentication deferral

When `MACKey` is set on `ChannelState`, every frame is sealed with
**HMAC-SHA256** over `header||payload` (32-byte trailer) per IP-C-0001. This is
an engineering MAC for local IPC tests — **not** a release claim of
confused-deputy resistance without OS isolation (IP-A-0001) and crypto review.

Unauthenticated channels (`MACKey == nil`) remain available for unit tests of
length/role/sequence policy only.

## Alternatives considered

- **Raw length-prefixed blobs:** rejected; no role/sequence policy.
- **gRPC/Cap’n Proto:** rejected for M1/M2 core; large dependency and ambient
  authority surface.
- **Full AEAD now:** deferred; needs IP-C suite selection.

## Risk analysis

Mitigates unbounded reads and trivial role confusion in tests. Residual risk:
missing MAC allows a compromised peer process with channel access to forge
frames — accepted only inside OS isolation envelopes from IP-A-0001.

## Verification strategy and acceptance criteria

- Unit: round-trip, role mismatch, duplicate sequence, close, oversize payload.
- Property: sequences never go backwards on a live channel.
- Later M2: hostile IPC suite under VER-ARCH-001 platform probes.
- Acceptance mapped to INT-IC1-0001 inventory + INT-IC3-0002 admission.

## Retirement/rollback plan

Bump `version` and magic for incompatible changes; dual-run during M2 bring-up.

## Dissent and unresolved questions

- Exact AEAD construction and key ratchet (IP-C).
- Whether supervisor-mediated pairing tokens are required before first frame
  (M2 prelude now derives pair MAC keys via provisional HKDF in
  `supervisor.OpenFabric`).
- Queue credit / windowing beyond simple depth counters.

## Decision and approvals

Draft — implementation exists under `internal/ipc` against this text; approvals
open.
