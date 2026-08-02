# Authenticated remote push (M1c + M1d engineering increments)

Status: **Implemented engineering preview (not the product daemon)**  
Package: `internal/remotesync`  
Commands: `integris serve`, `integris push`

## Purpose

Cross the network boundary with a **small, executable** vertical slice:

```text
push client  --(IP-P frames + peer/archive auth + AEAD)-->  serve
              FileBegin / FileAck / FileChunk / FileEnd
                                                         stage → localsync apply
                                                         (journaled)
```

This reuses `internal/protocol`, `internal/session`, `internal/crypto`, and
`internal/localsync`. It is **not** privilege-separated `integrisd`, not PKI,
and not bidirectional sync.

## Supported

- TCP transport with self-delimiting INTPRO01 frames
- Version + suite negotiation (`integris-aead-v0`)
- Mutual HMAC peer-auth (`i2r` + `r2i`) and archive-auth (IP-C-0002 provisional)
- ChaCha20-Poly1305 traffic keys derived from shared root + transcript
- Unidirectional directory push (regular files + directories)
- **Chunked file transfer** (default chunk 256 KiB; override with `-chunk-size`)
- **Mid-file resume** across reconnects via durable partials under
  `destination/.integris/recv-partial/`
- Receiver staging under `destination/.integris/recv-stage/` then
  `localsync.Sync` (SHA-256 verify + journal on dest)
- Wrong shared key fails closed at handshake
- Legacy single-frame `File` messages still accepted by serve (tests / old peers)

## Explicitly not supported

- Long-term node identity / certificates / Noise/TLS final suite
- Privilege-separated net/auth/apply processes
- Bidirectional sync, deletions, watchers
- Compression, deduplication, multi-client scheduling
- Cross-host resume identity beyond matching `(rel, size, digest)` on the same
  destination tree

## Shared key (PSK)

Both peers need the same **32-byte root key** (`-key` hex/raw or `-keyfile`).

### Per-peer allow-list (M2i, `integrisd`)

When the receiver uses a named peer keyring (`integrisd serve -peer-key ID=PATH`),
the push client must send an unauthenticated peer prologue (`INTPID01`) before
negotiate (`integris push -peer ID`) and use that peer’s 32-byte key. The MAC key
is bound to the peer id. Unknown IDs and wrong keys fail closed at handshake.
This is still PSK material — not PKI.

Derived locally:

| Material | Derivation |
|---|---|
| Frame MAC | `ChannelMACKey(root, "push", "serve")` |
| Peer auth | `PeerAuthKey(root, sessionID)` |
| Archive auth | `ArchiveAuthKey(root, sessionID)` |
| Traffic AEAD | `TrafficKey(root, transcript, sessionID, suite)` |

Session IDs are random per connection (chosen by push, learned by serve from
the first frame).

## CLI

```sh
# terminal A
go run ./cmd/integris serve -destination ./B -key "$HEX32" -addr 127.0.0.1:9100 -once

# terminal B
go run ./cmd/integris push -source ./A -addr 127.0.0.1:9100 -key "$HEX32"
go run ./cmd/integris push -source ./A -addr 127.0.0.1:9100 -key "$HEX32" -chunk-size 65536
```

## Application messages (TypeData plaintext)

| Code | Name | Role |
|---|---|---|
| 1 | Manifest | entry list with digests |
| 2 | ManifestOK | serve ack |
| 3 | File | legacy single-frame body (size-limited) |
| 4 | Commit | request apply |
| 5 | Result | ok / error string |
| 6 | FileBegin | rel, mode, digest, size |
| 7 | FileAck | resume offset (bytes already held) |
| 8 | FileChunk | offset + payload |
| 9 | FileEnd | rel + digest confirmation |

Chunking is at the **application** layer inside TypeData so control messages
(manifest/commit/result) share the same session without
`Driver.TrackDataChunks`.

## Resume layout

| Path | Role |
|---|---|
| `destination/.integris/recv-partial/<rel>.part` | durable partial bytes |
| `destination/.integris/recv-partial/<rel>.meta.json` | rel, size, digest, offset |
| `destination/.integris/recv-stage/` | completed files before localsync apply |
| `destination/.integris/local.jrn` | localsync journal after Commit |

On `FileBegin`, serve replies `FileAck(offset)` from matching meta + `.part`
size. Push seeks and continues. Interrupt mid-file persists meta; a later push
to the same destination resumes. After successful apply, `recv-stage` is cleared.

`localsync.ResolveRoots` allows a source under `destination/.integris/` so
serve can apply from `recv-stage` without nested-root refusal.

## Security notes

- PSK compromise allows full impersonation; treat as lab credential only.
- Frame MACs and AEAD are provisional engineering suites pending crypto review.
- Serve applies into the destination with localsync journal under `.integris/`.
- No ambient multi-tenant isolation in this CLI.

## Privilege-separated receive

M2a wires this protocol into `integrisd serve` (`integrisd-net` +
`integrisd-apply`). See [daemon-m2a.md](daemon-m2a.md). Monolithic
`integris serve` remains for single-process debugging.

## Next increment (proposed)

Harden resume identity / multi-file scheduling, or insert auth/parser roles
(M2b) before PKI.
