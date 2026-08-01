# Criticality policy

Status: **Normative baseline**

## Classes

### IC-1 — Catastrophic integrity

A violation can cause irreversible loss, unauthorized overwrite, escape from an
assigned root, application of unauthenticated or wrong-archive content,
acceptance of corruption, or compromise of long-term keys.

Required: semi-formal or formal specification; independent technical and
security review; negative, generative, fuzz, integration, and fault-injection
tests as applicable; structural coverage rationale; reproducible evidence; no
implicit waiver. The author cannot be the sole approver.

### IC-2 — Recoverability and consistency

Includes abrupt stop, incomplete journal, resource exhaustion, network loss,
restart during publication, missed filesystem events, and concurrent local
change. Required: explicit state/recovery specification, crash testing at each
persistence point, idempotency tests, and independent review.

### IC-3 — Operational security

Includes diagnostics, administration, configuration, updates, observability,
and resource limits. Required: misuse cases, secure defaults, least privilege,
upgrade/rollback tests, and operational documentation.

### IC-4 — Performance and convenience

Includes throughput, compression, parallelism, deduplication, and usability.
Measured improvements must not weaken IC-1 or IC-2. When classes conflict, the
higher-integrity requirement wins or the system refuses the operation.

**INT-IC4-0001** further requires that every declared platform exercise all
qualifying stable native OS/filesystem optimizations; ignoring available
platform capacity is not an acceptable IC-4 posture.

## Classification process

Classify by credible worst-case consequence, not implementation size. A change
inherits the highest class of any requirement, invariant, trust boundary, or
recovery behavior it affects. Uncertainty defaults one class more critical until
analysis resolves it.

Waivers must be explicit IP-S records with scope, expiry, compensating controls,
residual risk, named owner, and independent approval. There are no permanent or
silent waivers for IC-1.
