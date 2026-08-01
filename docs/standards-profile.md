# Standards and guidance profile

Status date: **2026-08-01**

This profile records influences, not certifications. Only publicly verifiable
claims are made; paid normative text must be consulted by competent assessors
before any conformance claim.

| Source | Version/status adopted | Use in Integris | Claim boundary |
|---|---|---|---|
| ISO/IEC/IEEE 12207 | 2026, published 2026-04 | lifecycle coverage from conception through retirement | process influence only |
| IEC 61508-3 | 2010, current edition at baseline date | graded techniques, lifecycle evidence, independence concepts | no SIL or functional-safety claim |
| NIST SP 800-218 SSDF | v1.1 final | secure development practice matrix | v1.2 was draft; not normative here |
| CISA Secure by Design | current public guidance | secure defaults and producer responsibility | guidance, not certification |
| SLSA | v1.2 approved | build/source supply-chain targets and provenance | track/level claim only after evidence |
| in-toto | Attestation Framework v1.0 stable | provenance envelope and step evidence | format use only |
| Sigstore | current verification/bundle model | identity signing and transparency proof | public service optional |
| Go | 1.26.5, released 2026-07-07 | pinned bootstrap compiler/runtime | compiler identity is not a correctness claim |
| RFC 2119 + RFC 8174 | current | normative keyword interpretation | capitals only |

## Review cadence

The assurance owner reviews this profile at least every six months and before a
stable release. Drafts are monitored but cannot silently replace normative
versions. Updating a source requires impact analysis, migrated mappings,
verification changes, and an approved IP-G or IP-S where critical properties
change.

## Primary public sources

- https://www.iso.org/standard/90219.html
- https://webstore.iec.ch/en/publication/5517
- https://csrc.nist.gov/pubs/sp/800/218/final
- https://csrc.nist.gov/projects/ssdf/publications
- https://www.cisa.gov/securebydesign
- https://slsa.dev/spec/v1.2/
