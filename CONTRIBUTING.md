# Contributing

Integris treats changes as assurance claims. A green test run is necessary but
not sufficient.

## Before changing anything

1. Classify the change IC-1 through IC-4 using `docs/criticality-policy.md`.
2. Link an existing requirement, hazard/threat, and verification record, or add
   them in the same change.
3. Use an Integris Proposal for durable architecture, protocol, persistent
   format, security, cryptographic, operational, or governance decisions.
4. Identify the required independent reviewers before implementation.

## Local gate

```sh
make verify
```

This formats and tests the Go assurance tool, checks static analysis, validates
all assurance references, and verifies that generated traceability is current.

## Go rules

All Go code follows `docs/go-profile.md`. In particular: no `unsafe`, no cgo,
no shell execution, no unowned goroutines, bounded external inputs, deterministic
ordering, explicit cancellation, and no panic for expected operational events.

## Pull requests

Complete every applicable item in the pull request template. Keep commits
reviewable and signed when contributor infrastructure supports it. Never place
vulnerability details, secrets, personal data, real archive contents, or private
paths in issues, fixtures, logs, or commits.

Security reports follow [SECURITY.md](SECURITY.md), not public issues.
