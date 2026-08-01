# Filesystem capability model

Status: **Pre-implementation normative specification**

## Capability result

Each source feature and target capability resolves to exactly one result:

- `LOSSLESS`: represented with equivalent semantics;
- `WRAPPED`: preserved in a documented reversible envelope;
- `UNREPRESENTABLE`: target cannot preserve it;
- `POLICY_FORBIDDEN`: technically possible but prohibited;
- `UNKNOWN`: not reliably detected or characterized.

The default for `UNREPRESENTABLE` and `UNKNOWN` is refusal before authorization.
`WRAPPED` requires an accepted format specification and restoration test. No
configuration default permits silent loss.

## Capability vector

The immutable per-session vector records filesystem/volume identity and version,
case sensitivity/preservation, Unicode behavior, name encoding/limits, symlink
and hard-link semantics, ACLs, extended attributes, BSD flags, sparse extents,
resource forks, time resolution/range, user/group identity mapping, mount points,
special objects, rename atomicity, file/directory sync semantics, copy-on-write,
snapshots, and durability limitations.

Discovery is bounded and non-destructive. Where a fact needs an empirical probe,
the probe runs in an isolated scratch directory on the same filesystem and its
result is journaled by digest. Capability changes invalidate the plan.

## Comparison and planning

Planning compares source semantics, target vector, and explicit policy. Results
are canonically sorted by path and capability identifier. Any lossy or unknown
result blocks authorization and produces a precise preflight report. IC-4
optimization may select among equivalent representations only after equivalence
has verification evidence.

## Publication guarantee

No global tree atomicity is claimed. A platform/filesystem publication profile
must state the linearization point, visibility unit, required sync sequence,
crash outcomes, directory durability, overwrite behavior, and rollback boundary.
Unsupported or unverified profiles fail closed.
