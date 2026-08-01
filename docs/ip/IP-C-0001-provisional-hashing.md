# IP-C-0001: Provisional M1 hashing and commitment suite

- Status: Draft
- Category: IP-C
- Authors: Integris maintainers
- Reviewers: cryptography, security, assurance
- Created: 2026-08-01
- Supersedes:
- Requirements: INT-IC2-0001, INT-IC1-0003, INT-IC1-0004
- Anchors: `docs/specifications/cryptography.md`, IP-F-0001, IP-A-0002
- Unlocks: stable digests for journal/plan/config; does **not** unlock release
  crypto claims

## Motivation

M1 kernels already commit journal records, plans, configuration, and capability
vectors. Without a ratified hash, those digests are informal. This IP locks a
**provisional** hashing choice for engineering evidence while forbidding any
claim of cryptographic suite stability pending independent review.

## Decision drivers and requirements

- Cryptography.md: invent no primitive; suite selection needs IP-C and review.
- IP-F-0001 already uses SHA-256 preimages for journal commitments.
- Session mutual authentication and traffic protection remain out of scope here.

## Proposed decision

### Hash for M1 commitments

| Use | Algorithm | Notes |
|---|---|---|
| Journal payload digest | SHA-256 | `codec.SHA256` |
| Journal record commitment | SHA-256 over canonical preimage | IP-F-0001 |
| Plan body digest | SHA-256 | IP-S-0002 |
| Configuration digest | SHA-256 over canonical JSON | `internal/config` |
| Capability vector digest | SHA-256 | `internal/fsmodel` |
| Path/archive pseudonyms | SHA-256 keyed commitment | observability |
| Local IPC frame MAC | HMAC-SHA256 | `internal/ipc` when MACKey set; provisional |

Output size is 32 bytes (`codec.Digest`).

### Explicit non-decisions (deferred)

- Session AEAD / handshake (Noise, TLS, or custom) — future IP-C
- Manifest/plan authorization signatures — future IP-C
- Release signing (Sigstore / offline roots) — release policy + IP-C
- KDF labels and key domains — future IP-C
- Journal AEAD beyond hash chaining — optional future IP-C

### Negotiation policy (when sessions exist)

Local minimum policy MUST reject unknown suites. A peer that offers only
post-quantum or alternate hashes before an accepted superseding IP is refused.
M1 session code (`internal/session`) does not negotiate crypto suites yet.

## Alternatives considered

- **SHA-512 / SHA3-256:** deferred; no M1 need; larger digests churn formats.
- **BLAKE2b:** deferred; less ubiquitous in Go stdlib-only posture.
- **Postpone any IP-C:** rejected; leaves IP-F/IP-S digests formally unbound.

## Risk analysis

SHA-256 is widely reviewed but length-extension applies to naive MAC constructions;
M1 uses SHA-256 as a digest/commitment primitive with explicit preimages, not as
HMAC-by-concatenation. Residual risk: suite change forces journal/plan version
bump and dual-read. No transport confidentiality is provided by this IP.

## Verification strategy and acceptance criteria

- Known-answer vectors for empty and fixed payloads in `internal/codec` tests.
- Cross-check plan golden digests remain stable under this IP.
- Independent cryptographic review required before promoting any EVD-PROTO or
  release crypto evidence to acceptance.
- Acceptance for **engineering digests only**; not for INT-IC1-0003 release use.

## Retirement/rollback plan

Superseding IP-C assigns a new suite ID and format version; old segments remain
readable under their recorded format_version.

## Dissent and unresolved questions

- Whether journal should move to SHA-256-based HMAC or KMAC before M3.
- Transcript hash for session negotiation once wire crypto exists.
- Domain separation strings — provisional prefixes deferred to format IPs.

## Decision and approvals

Draft — implements status quo of `internal/codec` SHA-256 helpers. Approvals and
independent crypto review are open; no stable-suite claim is made.
