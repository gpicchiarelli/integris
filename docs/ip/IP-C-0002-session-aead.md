# IP-C-0002: Provisional session AEAD (ChaCha20-Poly1305)

- Status: Draft
- Category: IP-C
- Authors: Integris maintainers
- Reviewers: cryptography, security, assurance
- Created: 2026-08-01
- Supersedes: (partially extends IP-C-0001 non-decision on session AEAD)
- Requirements: INT-IC1-0003
- Anchors: `docs/specifications/cryptography.md`, IP-P-0001, IP-C-0001
- Unlocks: engineering `TypeData` body sealing in `protocol.Driver`

## Motivation

Wire control frames can use HMAC, but content frames need confidentiality and
integrity under a provisional suite so M3 session work can proceed without
pretending a stable release crypto claim.

## Proposed decision

| Element | Choice | Notes |
|---|---|---|
| AEAD | ChaCha20-Poly1305 (`golang.org/x/crypto`) | 32-byte key, 12-byte nonce, 16-byte tag |
| Key derivation | HKDF-SHA256 | `SessionAEADKey` (session id only) or `TrafficKey` (suite \|\| session id \|\| transcript digest) |
| Suite negotiation | local allow-list | `session.LocalSuites`; refuse unknown peer-only suites |
| Nonce | `00 00 00 00 \|\| seq_be64` | per-direction sequence; never reuse under same key |
| AAD | `INTPRO01 \|\| type_u16le \|\| session_id \|\| seq_u64le` | binds frame metadata |
| Scope | `TypeData` bodies only when `Driver.AEADKey` set | control frames remain HMAC/MAC path |
| Peer auth (provisional) | Mutual HMAC-SHA256 proofs (`i2r` then `r2i`) over frozen negotiate digest | `AuthenticateProof` / `EncodePeerAuth`; body = dir\|\|proof; not Noise/TLS |

Suite ID strings: `integris-session-aead-chacha20poly1305-v1`,
`integris-peer-auth-hmac-sha256-v1`.

## Explicit non-decisions

- Handshake / Noise / TLS / post-quantum mutual authentication
- Key ratchet, 0-RTT, post-quantum KEM
- Journal or IPC AEAD replacement for HMAC
- Release acceptance of EVD-PROTO-001

## Risk analysis

Engineering-only. Sequence nonces are predictable; security relies on key
secrecy and no nonce reuse. Peer-auth HMAC proofs share a root key and bind
the frozen negotiation transcript for both directions — they are not a finished
handshake. Independent cryptographic review required before promoting protocol
evidence.

## Verification

- Known round-trip and AAD mismatch tests in `internal/crypto`
- Driver encode/decode of sealed `TypeData` in `internal/protocol`
- Transcript-bound `InstallTrafficKey` after Activate with matching peer keys
- Mutual HMAC peer-auth (`i2r`+`r2i`) + e2e negotiate→auth→AEAD path
- Session.tla `PeerAuthIsMutual` invariant
- EVD-PROTO-001 remains **planned**

## Decision and approvals

Draft — implementations under `internal/crypto` and `protocol.Driver`.
