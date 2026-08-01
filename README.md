<h1 align="center">Integris</h1>

<p align="center">
  <strong>Engineering baseline for a high-integrity replication system.</strong>
</p>

<p align="center">
  <a href="https://github.com/gpicchiarelli/integris/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/gpicchiarelli/integris/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/gpicchiarelli/integris/actions/workflows/formal.yml"><img alt="Formal" src="https://github.com/gpicchiarelli/integris/actions/workflows/formal.yml/badge.svg"></a>
  <a href="https://github.com/gpicchiarelli/integris/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/gpicchiarelli/integris/actions/workflows/codeql.yml/badge.svg"></a>
  <a href="https://github.com/gpicchiarelli/integris/actions/workflows/fuzz.yml"><img alt="Fuzz" src="https://github.com/gpicchiarelli/integris/actions/workflows/fuzz.yml/badge.svg"></a>
  <a href="https://github.com/gpicchiarelli/integris/actions/workflows/scorecard.yml"><img alt="OpenSSF Scorecard" src="https://img.shields.io/badge/OpenSSF-Scorecard-blue"></a>
  <a href="SECURITY.md"><img alt="Security policy" src="https://img.shields.io/badge/security-policy-green"></a>
  <a href="go.mod"><img alt="Go 1.26.5" src="https://img.shields.io/badge/Go-1.26.5-00ADD8?logo=go&amp;logoColor=white"></a>
  <a href="docs/platform-matrix.md"><img alt="Target platforms" src="https://img.shields.io/badge/platforms-macOS%20%7C%20FreeBSD%20%7C%20Linux%20%7C%20OpenBSD-0A7A3E"></a>
  <a href="formal/README.md"><img alt="TLA+" src="https://img.shields.io/badge/formal-TLA%2B-6B4FBB"></a>
  <a href="ROADMAP.md"><img alt="Milestone status" src="https://img.shields.io/badge/status-M0%20%E2%86%92%20M1-orange"></a>
  <a href="LICENSE"><img alt="BSD-3-Clause" src="https://img.shields.io/badge/license-BSD--3--Clause-blue"></a>
</p>

![Integris high-integrity replication and assurance laboratory](docs/assets/integris-hero.png)

Integris is the engineering baseline for a high-integrity replication system
targeting macOS, FreeBSD, Linux, and OpenBSD. It is designed around prior
specification, privilege separation, capability-oriented security, an
authenticated protocol, transactional application, verifiable persistence,
targeted formal methods, adversarial testing, and attestable supply chains.

> [!IMPORTANT]
> Integris is **not a usable replication daemon**, is **not certified**, and
> makes no SIL, safety-critical, or standards-conformance claim. Product
> kernels under `internal/` are reference implementations gated by draft IPs
> and incomplete IC-1 evidence — not a release.

## What is here

- machine-readable requirements, hazards, threats, and verification evidence;
- a fail-closed traceability validator and generated traceability matrix;
- security architecture, transaction, journal, protocol, filesystem, and
  cryptography specifications;
- executable TLA+ models for the transaction and session state machines;
- M1 reference kernels: path, codec, journal, plan, recovery, config, resource,
  deletion, fsmodel, authority, observability, IPC prelude, session, and
  protocol (`internal/`);
- evidence tooling (`integris-evidence`, `integris-verify-config`,
  `integris-release-digest`) and artifacts under `evidence/`;
- draft IPs under `docs/ip/` (IP-S/F/A/C/P series);
- a restricted Go profile and platform confinement matrix;
- review, change-control, release, vulnerability-response, and retirement rules;
- pinned, least-privilege GitHub workflows and a reproducible-build contract.

The governing invariant is:

> Every significant decision has a requirement, rationale, risk analysis,
> verifiable specification, verification method, produced evidence, and named
> approval role.

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

## Repository map

```text
assurance/       machine-readable assurance records
cmd/             assurance and evidence tooling
docs/            normative specifications and engineering policy
evidence/        produced or interim verification artifacts
formal/          executable formal models and model-checker configurations
internal/        M1 reference kernels (not a daemon)
.github/         review policy, templates, and automated controls
```

Normative words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are interpreted
as described by RFC 2119 and RFC 8174 only where they appear in capitals.

## Status

The project is transitioning **M0 → M1**: assurance baseline is in place; draft
IPs and executable reference kernels exist; IC-1 path/recovery evidence and
independent reviewers remain open. See [ROADMAP.md](ROADMAP.md).
No production release or compatibility promise exists yet.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
