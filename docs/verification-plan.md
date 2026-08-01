# Verification plan

Status: **Normative planning baseline**

## Layers

| Level | Purpose | Required examples |
|---|---|---|
| Model | disprove invariant violations in abstractions | TLA+ exhaustive checks, bounded liveness checks |
| Unit | deterministic kernel behavior | tables, boundaries, negative cases, mutation-sensitive assertions |
| Property | broad grammar/state exploration | generators, shrinking, model-derived oracles |
| Fuzz | hostile unstructured input | parsers, journal recovery, path components, protocol frames |
| Integration | real subsystem contracts | authenticated IPC, descriptor confinement, persistence ordering |
| System | end-to-end guarantees | hostile peer, wrong archive, crash/restart, resource saturation |
| Acceptance | declared operator outcome | recovery, upgrade, rollback, revocation, retirement |

## IC-1 minimum evidence

An IC-1 item needs its specified model or semi-formal invariant, independent
review, exhaustive boundary tests where the domain is finite, negative tests,
property/generative tests, continuous fuzzing where input is unbounded, fault
injection, platform integration evidence, and structural coverage rationale.
Coverage percentage alone is not acceptance evidence.

## Crash and persistence campaign

The harness injects termination before and after each meaningful write, sync,
rename, directory sync, journal append, and publication boundary. After restart,
an independent verifier checks: no unauthorized publication; journal prefix
validity; at most one confirmation; preservation of old or fully verified new
content according to the platform guarantee; idempotent repeated recovery; and
recoverability of quarantined destructive operations.

## Resource and adversarial campaign

Vary memory, disk (`resource.WithSoftFSIZE` → EFBIG; Darwin `hdiutil` volume → ENOSPC), file descriptors (`resource.WithSoftNOFILE`), CPU (`resource.WithSoftCPU` → SIGXCPU), queue depth, latency, loss, reordering,
disconnect, large counts, long names, sparse files, attributes, contention,
corrupt/truncated journals, altered manifests, replay, downgrade, and peer
Byzantine behavior within the documented distributed boundary.

## Evidence rules

Evidence records exact source revision, tool/version, platform, configuration,
seed/corpus, command, result, artifact digest, and reviewer. Failure artifacts are
retained and minimized without deleting the original. A planned test is not
evidence. Manual results need a second-person witness for IC-1 release use.
