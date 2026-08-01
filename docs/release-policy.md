# Release policy

Status: **Normative**

A release is an assurance decision, not a feature-completion event.

## Mandatory gate

- assigned requirements are bidirectionally traced and all required methods pass;
- there are no open IC-1 defects;
- residual IC-2 defects have explicit risk acceptance and recovery impact;
- applicable formal models pass and have implementation conformance evidence;
- crash recovery passes at every identified persistence boundary;
- every declared platform produces versioned confinement/filesystem evidence;
- artifacts are independently reproducible bit for bit;
- build provenance and complete SBOM are published;
- checksums, artifacts, provenance, and SBOM are signed;
- online Sigstore verification and an offline administrator-managed trust path
  are documented and tested;
- operator, recovery, upgrade, rollback, revocation, and retirement documents
  match the release;
- technical, security, assurance, and release roles approve; the release manager
  is not the sole approver.

## Artifacts

Each release bundle includes binaries, source archive, detached debug material,
SHA-256 digest manifest, SPDX or CycloneDX SBOM, SLSA provenance in an in-toto
envelope, test/evidence index, toolchain manifest, signatures/bundles, public
verification policy, and offline verification instructions.

## Reproducibility

Reproducible means independent parties recreate bit-for-bit identical specified
artifacts from the same source, environment, and instructions. A repeated build
by the release builder is only repeatability. Build environment, compiler,
modules, checksums, flags, locale, timestamps, paths, and debug separation are
fixed and published. At least one verifier is organizationally independent.

## Versioning and downgrade

Until M4, versions are `0.y.z` and compatibility is not promised. A stable
protocol/persistent-format version cannot be reused for changed semantics.
Installers and peers enforce a signed minimum-version policy. Rollback requires
explicit authorization and cannot bypass journal or archive compatibility.

## Revocation and withdrawal

The release manager can mark an artifact withdrawn, publish signed affected
digests, revoke signing identities where appropriate, state containment and
recovery steps, and preserve evidence. Withdrawal never deletes historical
provenance or the audit trail.
