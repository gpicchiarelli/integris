# Recovery kernel refinement notes

This package implements IP-S-0003 crash recovery. It is intentionally aligned
with `formal/transaction/Transaction.tla` invariants:

- `PublicationAuthorized`
- `PublicationPrepared`
- `ConfirmationSound` / `ConfirmationUnique`
- `NoInventedPublication`

TLC model checking of the TLA+ spec does **not** prove this Go code. Conformance
tests map journal record sequences and `FSObservation` fields onto the abstract
flags documented in `doc.go`. Residual gaps (richer terminal states than the
model `Recover` action, M1 progress/authorization payload conventions, broader
crash entry conditions) are listed there and must not be narrated as formal
proofs.

Evidence IDs `EVD-RECOVERY-001` and `EVD-TXN-001` stay `planned` until
independent review closes residual gaps. Campaign artifacts under
`evidence/recovery/` and `evidence/transaction/` are produced by
`integris-evidence` and are not automatic acceptance.
