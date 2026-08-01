# Supply-chain policy

Status: **Normative target; hosting controls pending**

## Source

Protected branches require review, passing checks, no force push, no branch
deletion, resolved conversations, and signed commits/tags when identity
infrastructure is available. GitHub configuration is external evidence and must
be audited; workflow files cannot prove that protection is enabled.

## Dependencies

Dependencies are minimized, declared, checksummed, license-reviewed, and pinned.
GitHub Actions are pinned to full commit digests with the release tag in a
comment. Automated updates must retain review. A critical dependency needs an
owner, threat review, replacement/retirement plan, and transitives inventory.
Bootstrap CI tools invoked through Go are pinned to exact module versions and
verified through the Go checksum database; release tooling requires a recorded
artifact digest in addition.

## Build

Release builds run in isolated ephemeral hosted environments, separated from
developer machines and release approval. The build definition generates signed
SLSA provenance, an SBOM, tests, and digests without exposing signing keys to
untrusted pull requests. The target is SLSA v1.2 Build L3 or the highest approved
level of the applicable track; this is a supply-chain claim, not product safety.

## Signing and transparency

Public releases use identity-bound Sigstore signing and transparency inclusion
bundles when suitable. Bundles are distributed with artifacts for offline proof
checking. Isolated deployments also support explicit offline roots and threshold
release signatures without depending on a public service.

## Reproducibility

The build definition sets `CGO_ENABLED`, target tuple, `-trimpath`, stable version
metadata, locale, timezone, module proxy/checksum policy, and `SOURCE_DATE_EPOCH`
derived from the signed source revision. Independent builders compare byte-level
digests. Differences block the claim and release.

## Primary references

- SLSA v1.2: https://slsa.dev/spec/v1.2/
- in-toto: https://in-toto.io/docs/specs/
- Sigstore verification: https://docs.sigstore.dev/cosign/verifying/verify/
- Reproducible Builds definition: https://reproducible-builds.org/docs/definition/
