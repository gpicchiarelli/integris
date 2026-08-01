# Formal models

These models target TLA+ / TLC 1.8.0. They abstract security properties; they do
not prove the Go implementation. Each product kernel must add model-conformance
tests and document abstraction gaps.

Run with a verified `tla2tools.jar`:

```sh
java -XX:+UseParallelGC -cp /path/to/tla2tools.jar tlc2.TLC \
  -config formal/transaction/Transaction.cfg formal/transaction/Transaction.tla
java -XX:+UseParallelGC -cp /path/to/tla2tools.jar tlc2.TLC \
  -config formal/session/Session.cfg formal/session/Session.tla
```

The CI workflow (`.github/workflows/formal.yml`) downloads release `v1.8.0`
from the TLA+ project and verifies SHA-256
`e22f8ffb4bacdea0a871f444dd94fe5fb0d8013b3388ae39e82e26f852c735d5` before
execution. It runs on changes under `formal/**` (or the workflow file) and via
`workflow_dispatch`; cancelled default-branch runs make the README Formal badge
report failing until a later green run.

Checked invariants:

- transaction publication implies prior authorization, preparation, and content
  verification;
- confirmation implies publication and occurs at most once;
- recovery does not invent publication or confirmation;
- an active session is mutually authenticated, archive-authorized, uses the
  highest mutually permitted version, and has not accepted replay;
- product mutation is unreachable from failed/incomplete sessions.
