# Destructive-operation specification

Status: **Pre-implementation normative specification**
Criticality: IC-1

Permanent deletion is disabled by default. A removal plan moves objects to a
same-volume quarantine with recoverable metadata and a retention deadline.

## Preconditions

- valid root sentinel with archive identity and format;
- opened root volume identity equals the authorized identity;
- complete, authenticated source manifest (an empty/incomplete origin blocks);
- canonical plan and separately signed destructive-operation authorization;
- count, percentage, logical bytes, physical bytes, and path-class thresholds
  all below policy limits;
- sufficient quarantine capacity and verified restoration path;
- immutable configuration/capability digests equal authorization.

Crossing any threshold is a hard stop, not a warning. Threshold arithmetic uses
overflow-safe conservative rounding; unknown size/count is over threshold.

## Quarantine

Each move is relative-descriptor based, journaled, and persisted on the same
volume before the source name is considered removed. Metadata records original
canonical identity, object identity, plan/authorization digest, quarantine name,
timestamps as observations, and retention policy. Name collision cannot replace
an existing quarantine object.

## Purge and restore

Restore is a new authorized transaction that refuses overwrite or identity
ambiguity. Purge requires expiry, a new explicit authorization, a verified
backup/recovery policy where configured, threshold re-evaluation, and auditable
evidence. Resource pressure cannot silently shorten retention; it suspends new
destructive operations and requests operator action.
