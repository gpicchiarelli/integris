# Assurance records

These JSON files are normative, reviewable source records. The standard library
only is used to validate them, minimizing bootstrap dependencies.

- `requirements.json`: atomic requirements with class, pre/postconditions,
  rationale, risks, specifications, methods, owner, and approval roles;
- `hazards.json`: preliminary safety hazard analysis;
- `threats.json`: STRIDE-linked security scenarios and residual risk;
- `verifications.json`: methods and exact acceptance criteria;
- `evidence.json`: planned versus produced evidence. Planned is never success.

Run `make assure` to validate identifiers and bidirectional references. Run
`go run ./cmd/integris-assure trace --root . --write` only when intentionally
updating the generated matrix, then review the diff. CI uses `--check`.

Changing JSON key order or whitespace is not semantically relevant, but records
must remain valid JSON with no duplicate object keys. The validator rejects
unknown top-level assumptions by using fixed Go structures; stricter JSON Schema
publication is planned before external tooling consumes the records.
