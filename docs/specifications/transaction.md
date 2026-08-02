# Replication transaction specification

Status: **Pre-implementation normative state model**
Formal model: `formal/transaction/Transaction.tla`
Protocol contract: [replication-protocol.md](replication-protocol.md) (INT-PROTO-0001)
covers the full replication cycle, atomicity, crash catalogue, and invariants
that this state model implements.

## Normal states

```text
CREATED → AUTHENTICATED → MANIFEST_VERIFIED → PLANNED → AUTHORIZED →
CONTENT_RECEIVED → PREPARED → VERIFIED → PUBLISHING → PUBLISHED → CONFIRMED
```

Terminal/side states are `SUSPENDED`, `CANCELLED`, `QUARANTINED`, `RECOVERING`,
and `IRRECOVERABLE`. Only the transition table and formal model may define edges.

## Transition contract

Each implementation transition has typed preconditions, filesystem effects,
mandatory journal records, required persistence barrier, linearization point,
recovery rule, cancellation rule, and fault-injection labels before/after every
effect. An unexpected state/record pair is quarantined, not guessed.

Authorization binds transaction ID, peer/node identities, archive identity,
manifest digest, canonical plan digest, immutable configuration digest,
capability-vector digest, destructive-operation summary, limits, and expiry/use
policy. Any mismatch invalidates it.

## Publication invariants

- no archive mutation before durable authorization and verified preparation;
- only content matching the authorized manifest and plan can be published;
- the opened root/volume identity must match authorization throughout;
- publication confirmation occurs at most once and only after the declared
  filesystem persistence sequence completes;
- recovery never widens authority or invents a transition;
- repeating recovery reaches the same stable state without duplicate effects.

## Cancellation and irreversibility

Cancellation before the publication linearization point removes or quarantines
staging without archive mutation. After it, recovery completes or restores only
as the platform publication profile permits. Global tree atomicity is never
implied. `IRRECOVERABLE` requires preserved evidence and explicit operator action;
it must never be reported as success.
