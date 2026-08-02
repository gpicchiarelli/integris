<h1 align="center">Integris</h1>

<p align="center">
  <strong>A privilege-separated sync and backup daemon for Unix servers.</strong>
</p>

<p align="center">
  <a href="docs/platform-matrix.md">macOS</a>
  ·
  <a href="docs/platform-matrix.md">FreeBSD</a>
  ·
  <a href="docs/platform-matrix.md">Linux</a>
  ·
  <a href="docs/platform-matrix.md">OpenBSD</a>
</p>

<p align="center">
  <a href="https://github.com/gpicchiarelli/integris/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/gpicchiarelli/integris/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/gpicchiarelli/integris/actions/workflows/formal.yml"><img alt="Formal" src="https://github.com/gpicchiarelli/integris/actions/workflows/formal.yml/badge.svg"></a>
  <a href="https://github.com/gpicchiarelli/integris/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/gpicchiarelli/integris/actions/workflows/codeql.yml/badge.svg"></a>
  <a href="https://github.com/gpicchiarelli/integris/actions/workflows/fuzz.yml"><img alt="Fuzz" src="https://github.com/gpicchiarelli/integris/actions/workflows/fuzz.yml/badge.svg"></a>
</p>

<p align="center">
  <a href="go.mod"><img alt="Go 1.26.5" src="https://img.shields.io/badge/Go-1.26.5-00ADD8"></a>
  <a href="formal/README.md"><img alt="TLA+" src="https://img.shields.io/badge/formal-TLA%2B-6B4FBB"></a>
  <a href="ROADMAP.md"><img alt="Milestone status" src="https://img.shields.io/badge/status-M0%20%E2%86%92%20M1-orange"></a>
  <a href="LICENSE"><img alt="BSD-3-Clause" src="https://img.shields.io/badge/license-BSD--3--Clause-blue"></a>
</p>

![Integris high-integrity sync and backup laboratory](docs/assets/integris-hero.png)

Integris is intended as a privilege-separated sync and backup daemon (`integrisd`):
it replicates explicitly authorized filesystem archives between mutually authenticated
nodes on macOS, FreeBSD, Linux, and OpenBSD. Operators configure archives, peers, and
policy; the daemon plans, transfers, journals, and recovers under least authority.
Protected properties are archive identity, containment, authenticity, integrity,
deterministic planning, recoverability, and truthful completion — not ambient
multi-writer sync or silent metadata loss.

This repository is the engineering baseline for that daemon. It is designed around
prior specification, privilege separation, capability-oriented security, an
authenticated protocol, transactional application, verifiable persistence, targeted
formal methods, adversarial testing, and attestable supply chains.

> [!IMPORTANT]
> **Not a usable sync or backup daemon — not certified.** Integris makes no SIL,
> safety-critical, or standards-conformance claim. Product kernels under `internal/`
> are reference implementations gated by draft IPs and incomplete IC-1 evidence —
> not a release. The local CLI
> [`integris sync`](docs/localsync.md) is a first vertical engineering increment
> (unidirectional directory sync only); it is not authenticated replication and
> not `integrisd`.

## Local sync increment

Unidirectional local sync (source → destination) with explicit plan/apply
separation and content-hash verification:

```sh
go run ./cmd/integris sync -source ./A -destination ./B
go run ./cmd/integris sync -source ./A -destination ./B -json
```

Journaled crash resume is on by default (`destination/.integris/local.jrn`).
Details, limits, and exit codes: [docs/localsync.md](docs/localsync.md).

Authenticated remote push with chunked/resumable transfer (PSK engineering
preview):

```sh
go run ./cmd/integris serve -destination ./B -key "$HEX32" -addr 127.0.0.1:9100 -once
go run ./cmd/integris push -source ./A -addr 127.0.0.1:9100 -key "$HEX32"
go run ./cmd/integris push -source ./A -addr 127.0.0.1:9100 -key "$HEX32" -chunk-size 65536
```

See [docs/remotesync.md](docs/remotesync.md).

Privilege-separated receive (M2a–M4h engineering preview — full eight-role
receive chain under the supervisor; PSK or per-peer keyring held by
`integrisd-auth`; parser/plan/index/journal/audit/net/apply as separate OS
processes; optional `-strict-launch` for fail-closed confinement):

```sh
go run ./cmd/integrisd serve -destination ./B -key "$HEX32" -addr 127.0.0.1:9100
go run ./cmd/integrisd serve -destination ./B -key "$HEX32" -addr 127.0.0.1:9100 -once
go run ./cmd/integris push -source ./A -addr 127.0.0.1:9100 -key "$HEX32"
go run ./cmd/integrisd serve -destination ./B \
  -peer-key alice=./alice.key -addr 127.0.0.1:9100
go run ./cmd/integris push -source ./A -addr 127.0.0.1:9100 \
  -keyfile ./alice.key -peer alice
```

See [docs/daemon-m2a.md](docs/daemon-m2a.md).

## What is here

- machine-readable requirements, hazards, threats, and verification evidence;
- a fail-closed traceability validator and generated traceability matrix;
- security architecture, transaction, journal, protocol, filesystem, and
  cryptography specifications;
- executable TLA+ models for the transaction and session state machines;
- M1 reference kernels: path, codec, journal, plan, recovery, config, resource,
  deletion, fsmodel, authority, observability, IPC prelude, session, and
  protocol (`internal/`);
- first executable vertical slice: `internal/localsync` + `cmd/integris sync`;
- evidence tooling (`integris-evidence`, `integris-verify-config`,
  `integris-release-digest`) and artifacts under `evidence/`;
- draft IPs under `docs/ip/` (IP-S/F/A/C/P series);
- a restricted Go profile and platform confinement matrix;
- review, change-control, release, vulnerability-response, and retirement rules;
- pinned, least-privilege GitHub workflows and a reproducible-build contract.

The governing invariants are:

> Every significant decision has a requirement, rationale, risk analysis,
> verifiable specification, verification method, produced evidence, and named
> approval role.

> On every declared platform, Integris must use all qualifying stable native
> operating-system and filesystem optimizations — portable fallbacks are
> degraded mode only (**INT-IC4-0001**).

## Start here

1. Read the [assurance case](docs/assurance-case.md).
2. Review the [scope and claims](docs/scope-and-claims.md).
3. Inspect the [requirements](assurance/requirements.json) and generated
   [traceability matrix](docs/traceability.md).
4. Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change.
5. Run the local quality gate:

```sh
make verify
```

Optional: regenerate kernel evidence campaigns (writes under `evidence/`):

```sh
make evidence
```

Validate a configuration document without side effects:

```sh
go run ./cmd/integris-verify-config -config path/to/config.json
```

Write an engineering input digest manifest (not a release acceptance):

```sh
make release-digest
```

Go 1.26.5 is the pinned bootstrap toolchain. Milestone entrance/exit criteria
are in [ROADMAP.md](ROADMAP.md).

Install binaries and manual pages (portable default
`${PREFIX}/share/man`; traditional BSD layout with
`MANDIR=${PREFIX}/man`):

```sh
make PREFIX=/usr/local install
make man-lint
man integris
man 8 integrisd
```

See [man/README.md](man/README.md).

## Repository map

```text
assurance/       machine-readable assurance records
cmd/             assurance and evidence tooling
docs/            normative specifications and engineering policy
evidence/        produced or interim verification artifacts
formal/          executable formal models and model-checker configurations
internal/        M1 reference kernels (not a daemon)
man/             mdoc manual pages (sections 1, 7, 8)
.github/         review policy, templates, and automated controls
```

Normative words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are interpreted
as described by RFC 2119 and RFC 8174 only where they appear in capitals.

## Status

The project is transitioning **M0 → M1**: assurance baseline is in place; draft
IPs and executable reference kernels exist; IC-1 path/recovery evidence and
independent reviewers remain open. See [ROADMAP.md](ROADMAP.md).
No production release or compatibility promise exists yet.

## License and trademarks

Copyright (c) 2026 Integris contributors. Licensed under the
[BSD 3-Clause License](LICENSE). See [NOTICE](NOTICE).

Third-party names (macOS, FreeBSD, Linux, OpenBSD, Go, TLA+, and others) are
used only to identify platforms and tools. They remain the property of their
owners; no affiliation or endorsement is claimed. See [TRADEMARKS.md](TRADEMARKS.md).
