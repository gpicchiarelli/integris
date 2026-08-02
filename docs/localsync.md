# Local unidirectional sync

Status: **Implemented engineering increments (not the product daemon)**  
Package: `internal/localsync`  
Command: `integris sync`

## Purpose

Executable vertical slices that are really testable before network/auth:

1. **M1a** — scan → plan → apply → verify (staged rename + SHA-256)
2. **M1b** — append-only journal + crash resume (this document covers both)

This is **not** `integrisd`, not authenticated replication, and not a
production-readiness claim.

## Supported

- Unidirectional sync: source directory → destination directory
- Regular files and directories
- Deterministic planning (`mkdir`, `copy`, `replace`, `skip`)
- SHA-256 content digests (IP-C-0001 provisional)
- Safe publication: temp → write → `SyncFile` → verify → `chmod` → `rename` → dirsync
- Structured JSON result (`-json`)
- Plan-only mode (`-plan-only`)
- Cleanup of leftover `.integris.<hex>.tmp` files
- **Durable journal** under `destination/.integris/` (IP-F-0001 segment)
- **Crash resume**: interrupted apply reloads the persisted plan and continues
  from the next incomplete operation
- Idempotent re-run after confirmation (new skip-only plan or no-op path)

## Journal layout

| Path | Role |
|---|---|
| `destination/.integris/` | Metadata root (mode `0700`); never synced as content |
| `destination/.integris/local.jrn` | Append-only commitment-chained journal |
| `destination/.integris/last-plan.json` | Snapshot of the active plan (digest-bound) |

Record types used: `observation`, `plan_digest`, `authorization` (local label),
`progress` (per completed op), `recovery` (resume mark), `confirmation`,
`cancellation` (superseded plan).

Torn journal tails are truncated to the longest valid prefix before append.

## Resume rules

1. If an incomplete transaction exists for the same absolute source and
   destination roots, Integris **does not replan**. It loads `last-plan.json`,
   checks the digest against the journal, appends a `recovery` record, and
   applies from `NextOp`.
2. Progress is journaled only **after** a successful op (including post-rename
   verify for files). A crash before that point retries the same op.
3. A confirmed transaction with an identical rebuilt plan digest short-circuits.
   After a successful copy plan, a later run usually builds a skip-only plan and
   starts a new short transaction — that is expected.

## Explicitly not supported (yet)

- Network transport, daemon, peer authentication
- Bidirectional sync and conflict merge
- Deletions / quarantine (destination-only files are left untouched)
- Symlinks, devices, sockets, FIFOs (`unsupported`)
- Continuous filesystem watching
- Block-level incremental transfer, compression, deduplication
- ACL / xattr / resource fork / BSD flag preservation beyond Unix mode bits
- Case-insensitive collision detection beyond byte-exact relative paths
- Multi-file atomicity (journal makes **progress** durable, not one tree commit)

## Security model

| Control | Behaviour |
|---|---|
| Path grammar | `internal/path` (no `..`, no absolute forms, Unicode NFC) |
| Symlinks | Never followed; refused at roots and entries |
| Open | Unix: `O_NOFOLLOW` |
| Staging | Temps mode `0600` in the destination directory only |
| Escape | `joinUnder` rejects paths outside the destination root |
| Source | Never modified |
| Metadata | `.integris` skipped by Scan on both trees |
| TOCTOU | Source re-hashed at apply; mismatch → `conflict` |

### Residual risks

- Concurrent writers on source/dest during apply
- Power loss after rename but before directory sync (platform-dependent)
- Case-insensitive volume aliases
- Local “authorization” is a journal label only — not cryptographic peer auth

## Atomicity and durability

**Per file:** live path replaced only via `rename` of a verified temp.  
**Per sync:** journal records completed ops; resume continues the remainder.  
**Not claimed:** global tree atomicity; “all or nothing” across files.

Durability mechanism is reported as `platform.DurabilityMechanism()` (`fsync` /
Darwin `F_FULLFSYNC`).

## Exit codes (`integris sync`)

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Sync/runtime failure |
| 2 | Invalid usage or arguments |
| 3 | Unsafe path |
| 4 | Unsupported filesystem object |

## CLI

```sh
go run ./cmd/integris sync -source ./A -destination ./B
go run ./cmd/integris sync -source ./A -destination ./B -json
go run ./cmd/integris sync -source ./A -destination ./B -plan-only -json
go run ./cmd/integris sync -source ./A -destination ./B -no-journal   # not crash-safe
go run ./cmd/integris sync -source ./A -destination ./B -journal /path/to.jrn
```

## Result fields (JSON)

Includes M1a fields plus `journal_path`, `resumed`, `plan_digest_sha256`,
`transaction_id`.

## Package notes

| Path | Role |
|---|---|
| `internal/localsync` | Scan, plan, apply, journaled sync |
| `internal/journal` | IP-F-0001 segment reader/writer |
| `internal/path` | Logical path grammar |
| `internal/codec` | Digests / record envelope |
| `internal/platform` | SyncFile / SyncDir |
| `internal/plan` | IP-S-0002 capability planner (**not** used here) |

## Related increment

Authenticated TCP push/serve that stages into this engine:
[remotesync.md](remotesync.md) (M1c).
