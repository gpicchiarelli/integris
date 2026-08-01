# Cryptographic design constraints

Status: **Constraints only; suite selection requires IP-C and independent review**

Integris invents no primitive and will not stabilize a cryptographic suite before
specialist review and public test vectors.

## Key domains

- node identity authentication;
- ephemeral session agreement and traffic protection;
- manifest/plan authorization signatures;
- journal record authentication/chain commitment;
- release artifact signing;
- offline recovery and administrative trust roots.

Keys are distinct by purpose and context. A KDF label binds product, protocol
version, suite, role, direction, node identities, archive identity, session ID,
and purpose. Encryption and authentication nonces cannot repeat under a key.

## Lifecycle

For every key type, an IP-C defines generation, entropy source, permitted store,
exportability, access process, activation, maximum age/use, rotation overlap,
revocation, compromise response, replacement, recovery, backup, and destruction.
Long-term private identity keys are referenced through OS key stores or isolated
signers where available and are not passed to network/parser processes.

## Algorithm policy

Each protocol version defines a small ordered allow-list of complete suites.
Negotiation is transcript-bound and constrained by signed local minimum policy.
Unknown, deprecated, peer-invented, or partially matched suites are rejected.
Algorithm retirement includes affected data, re-sign/re-encrypt feasibility,
minimum-version rollout, offline environments, and rollback prevention.

## Required review and tests

Stable use requires independent cryptographic design and implementation review,
known-answer and cross-implementation tests, transcript/downgrade tests, nonce
exhaustion analysis, key-compromise scenarios, side-channel review appropriate to
the threat model, secure deletion limitations, and release evidence.
