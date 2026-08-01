# Configuration specification

Status: **Pre-implementation normative constraints**

Configuration has a versioned deterministic schema and canonical serialization.
Unknown critical fields, duplicate keys, ambiguous units, implicit environment
expansion, locale-sensitive values, and non-canonical encodings are rejected.

All units are explicit (`bytes`, `milliseconds`, absolute counts, basis points).
Durations and sizes have safe bounds. Destructive features, lossy conversion,
weak confinement, network listeners, and trust anchors have no permissive
defaults. Ordinary files never contain secrets; they contain typed references to
approved secret stores.

Startup parses and validates the complete configuration before acquiring product
authority. `verify-config` performs the same validation and canonical printing
without network, archive mutation, key use, or journal write. A session captures
an immutable canonical configuration digest. Reload creates new sessions; it
cannot mutate the policy of an active transaction.

Changes identify old/new digest, schema migration, affected requirements and
risks, authorization, activation boundary, rollback rule, and audit event. A
schema downgrade is refused unless an explicit signed migration proves no
critical semantic loss.
