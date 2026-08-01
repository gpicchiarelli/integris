# Observability and evidence specification

Operational logs are not primary integrity evidence. The verifiable transaction
journal is primary for transaction claims.

Channels are separated: operational events, security events, audit/evidence
chain, diagnostics, and metrics. Every event has a stable ID, severity,
component, archive pseudonym, transaction ID where applicable, monotonic local
sequence, cause category, and redaction class.

Never record keys, secrets, file contents, authentication material, raw remote
payloads, unnecessary personal data, or full paths when policy marks them
sensitive. Path references use transaction-scoped opaque identifiers or keyed
commitments. Error strings from peers or operating systems are sanitized before
crossing trust boundaries.

Backpressure cannot block an IC-1 persistence barrier indefinitely. Dropped
operational diagnostics increment a bounded metric and stable event; mandatory
security/journal evidence follows its own capacity policy and safely suspends
new transactions before exhaustion causes false success.
