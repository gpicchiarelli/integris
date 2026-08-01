# Retirement and disposal plan

Status: **Baseline; product procedures pending**

A supported version enters retirement through a signed notice identifying
affected versions/digests, end-of-support dates, replacement paths, archive and
journal compatibility, key consequences, and recovery options.

Retirement must preserve the ability to independently verify old journals,
release signatures, provenance, and SBOMs. Public verification material and
format specifications remain available. Signing keys are revoked or archived
under documented policy; revocation must not erase historical validity proofs.

Operators receive a dry-run export/verification procedure, migration tool,
rollback boundary, secure secret/key disposal guidance, and a read-only verifier
that does not require the retired daemon. Destructive cleanup is never automatic
and follows the same quarantine and authorization policy as live deletion.

Project abandonment triggers publication of known limitations, last-supported
digests, source and build instructions, open critical defects where disclosure
is safe, and custody arrangements for security reports and trust roots.
