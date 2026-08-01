# Restricted Go profile

Status: **Normative for all Go code**

## Toolchain

The M0 bootstrap toolchain is Go 1.26.5. Upgrades require passing the full gate,
reviewing release notes, recording the compiler identity, and an IP when language
or runtime behavior affects a critical property. Release builds use `CGO_ENABLED=0`
unless an isolated, reviewed platform adapter explicitly requires otherwise.

## Prohibited

- `unsafe` in IC-1/IC-2 and by default everywhere;
- cgo outside an isolated platform adapter with an accepted IP;
- `os/exec`, shell invocation, dynamic loading, plugins, embedded interpreters
  **except** the narrow allowance in [IP-A-0003](ip/IP-A-0003-supervised-launcher.md):
  among `internal/*` packages only `internal/launcher` may start subprocesses
  (no shell, no `PATH` search for role binaries, `EngineeringMode` required
  until a superseding IP defines the release path); `cmd/integris-*` tools may
  invoke host `git`/`go` for evidence builds only;
- reflection in IC-1 paths without a necessity and verification argument;
- panic for input, resource, network, storage, or other expected failures;
- unbounded reads, allocations, collections, queues, retries, or recursion;
- security decisions based on map iteration, wall-clock order, or goroutine order;
- goroutines without an owner, cancellation path, and joined termination;
- logging secrets, contents, or unredacted sensitive paths.

## Required

- validate length and count before allocation from external values;
- explicit integer overflow checks and canonical encodings;
- typed states and constructors that exclude invalid combinations;
- sorted keys before serialization, hashing, planning, or authorization;
- `context.Context` and finite deadlines for blocking operations;
- errors with stable categories and preserved causes, never string matching for
  control flow across trust boundaries;
- injected I/O and persistence boundaries for deterministic fault testing;
- zero-value behavior documented; destructive actions default disabled;
- package dependencies point inward toward small deterministic kernels.

## Enforcement

CI runs formatting, tests, `go vet`, assurance validation, and generated-file
checks. Later milestones add pinned static analyzers, fuzzing corpora, coverage
rationales, race testing, vulnerability scanning, and platform builds. A tool
finding may be suppressed only by a reviewed, expiring record linked to risk.
