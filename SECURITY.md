# Security policy

## Supported versions

Integris has no production release. The `main` branch receives security fixes,
but must not be deployed as a replication service.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository. Do not open a
public issue and do not include real secrets or data. Include affected revision,
preconditions, impact, a minimal reproducer if safe, and suggested mitigations.

If private reporting is unavailable, contact the repository owner through a
private channel listed on the GitHub organization profile. No project security
email is invented here because an unmonitored address would create false trust.

## Response targets

Acknowledgement and remediation times are targets, not warranties:

| Severity | Acknowledge | Initial assessment |
|---|---:|---:|
| Critical | 1 business day | 2 business days |
| High | 2 business days | 5 business days |
| Medium/Low | 5 business days | 10 business days |

The response team assigns an IC class, preserves evidence, determines affected
releases, prepares revocation/mitigation instructions, and coordinates a fix and
advisory. Disclosure timing is agreed with the reporter where possible.

## Cryptographic and safety note

No cryptographic design or safety property in this pre-release repository has
yet received the independent specialist review required for a stable release.
