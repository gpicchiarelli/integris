// Package localsync implements executable local sync increments for Integris:
// deterministic, unidirectional directory synchronization (source → destination)
// with explicit planning, staged publication, content-hash verification, and
// an IP-F-0001 journal for crash resume.
//
// Scope:
//   - regular files and directories only;
//   - no deletions, network, daemon, authentication, or watchers;
//   - Plan never mutates the filesystem; Apply never mutates the source;
//   - journal + plan snapshot under destination/.integris/ (skipped by Scan).
//
// Content integrity uses SHA-256 (IP-C-0001 provisional). Path components in
// plans obey internal/path grammar (no "..", no absolute forms, Unicode NFC).
//
// Atomicity and durability are limited to what the host filesystem provides
// (see docs/localsync.md).
package localsync
