# Platform-native optimization

Status: **Normative design target**

Owner: Technical owner
Related requirement: INT-IC4-0001

## Invariant

On every declared platform (macOS, FreeBSD, Linux, OpenBSD), Integris **MUST**
discover, prefer, and exercise every applicable **stable** native operating-system
and filesystem facility that improves throughput, latency, durability signaling,
zero-copy transfer, cloning/reflinking, event notification, memory mapping, or
confinement for the local component role.

Integris **MUST NOT** ship a release path that leaves such a facility unused when
the facility:

1. is available on the declared minimum OS version for that port;
2. preserves all IC-1 and IC-2 semantics (including fail-closed refusal); and
3. has an accepted adapter IP or is covered by an existing platform profile.

When a native facility would weaken a higher-criticality requirement, Integris
**MUST** refuse the unsafe use or record an explicit IP waiver — it **MUST NOT**
silently select a weaker portable path while claiming native capability.

## Portable fallbacks

Portable or lowest-common-denominator implementations **MAY** exist only as
explicitly degraded modes. Degraded mode:

- **MUST** be recorded in the platform capability vector for the session;
- **MUST NOT** be the sole production path on a platform that offers a qualifying
  native facility;
- **MUST NOT** create a release artifact that claims full platform support while
  omitting declared native optimizations.

## Representative facilities (non-exhaustive)

Ports **MUST** inventory and track adoption of facilities at least in these
classes. Exact APIs evolve with accepted IPs and empirical platform evidence.

| Class | Examples (illustrative) |
|---|---|
| Bulk transfer | `sendfile`, `copy_file_range`, `splice`, platform clone/reflink — **adopted (Darwin):** `platform.CloneFile` → `clonefile` with exclusive-copy degraded fallback (`CopyXattr` + `CopyBSDFlags` + `CopyACL` when cgo); consumer `recovery.FilePublisher.PublishFrom`; CapCOW discovery in `fsmodel.ProbeScratch` |
| Metadata / ACL | **adopted (Darwin cgo):** `platform.ACLRoundTrip` / `CopyACL` (`acl_*`); `CopyXattr` / `CopyBSDFlags` on degraded clone; CapACL/CapXattr/CapBSDFlags probe + CloneFile consumers; CapSparse/CapResourceFork/CapTimes/CapUnicode also empirical |
| I/O completion | `kqueue`, `epoll`, accepted bounded `io_uring` adapters where IP-approved |
| Durability | platform-correct `fsync`/`fdatasync`/`F_FULLFSYNC`, directory sync, rename linearization profiles — **adopted:** `internal/platform.SyncFile` / `SyncDir` (Darwin `F_FULLFSYNC`; other Unix `fsync`) wired through journal, recovery publish/persist, quarantine, and key-FD materialization |
| Notification | `kqueue` VNODE / `NOTE_*`, `inotify`/`fanotify` only behind reviewed adapters |
| Confinement | strongest stable primitives per [platform-matrix.md](../platform-matrix.md) (`pledge`/`unveil`, Capsicum, Landlock+seccomp, Seatbelt/Hardened Runtime) |
| Identity / secrets | Keychain or OS key stores where an accepted IP allows them |

Absence of an entry above is not permission to ignore a better native facility
discovered later; the inventory **MUST** grow with platform evidence.

## Conflict rule

Per [criticality-policy.md](../criticality-policy.md): when a native optimization
conflicts with IC-1 or IC-2, the higher-integrity requirement wins or the
operation is refused. Performance never authorizes silent semantic loss,
ambient authority, or unverifiable persistence.

## Verification

See VER-PERF-001. Evidence records the capability vector, selected native
facilities, degraded-mode refusals, and benchmarks that show the release path
does not leave a qualifying facility unused.
