# Safe path resolution specification

Status: **Pre-implementation normative specification**
Criticality: IC-1

## Name grammar

A protocol path is a non-empty sequence of canonical name components. A
component is rejected if it is empty, `.`, `..`, absolute, contains NUL or a
platform separator, violates the negotiated encoding/normalization profile, or
exceeds the declared byte/scalar limit. Platform reserved names and ambiguous
normalizations are rejected before planning.

String validation does not authorize access.

## Resolution algorithm

1. Receive an already-open, policy-authorized root directory descriptor and its
   captured volume/filesystem identity.
2. For each canonical component, open relative to the held parent descriptor
   with no-follow semantics and the minimum required rights.
3. Verify after open that the object type, identity, link count constraints,
   mount/volume identity, and expected metadata satisfy the plan.
4. Retain the descriptor through mutation; never re-resolve an authorized string.
5. For creation, open and validate the parent chain, create a unique staged name
   with exclusive semantics, validate the created object, then publish according
   to the transaction specification.
6. Refuse symbolic links, unauthorized mount crossings, races, identity changes,
   unavailable required primitives, and unknown semantics.

Hard links are policy-controlled because separate names can identify the same
object. Special files are prohibited by default. Any platform adapter must expose
post-open facts, not emulate security with `filepath.Clean` or prefix checks.

## Safety properties

- no operation touches an object outside the conferred root or authorized mount;
- a changed object is detected before mutation where the platform permits;
- a validated name cannot be substituted by a symlink between check and use;
- resolution failure has no archive mutation effect;
- all externally derived lengths are bounded before allocation or syscall use.

## Verification

Use exhaustive component grammar tables, Unicode/property generators, fuzzing,
symlink/hard-link/mount race harnesses, post-open identity substitution tests,
and real-filesystem integration on every declared platform. Negative cases must
show no archive access, not merely an error result.
