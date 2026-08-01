// Package recovery implements idempotent crash recovery from a journal prefix
// and filesystem observations (IP-S-0003).
//
// # TLA+ alignment (formal/transaction/Transaction.tla)
//
// Abstract model flags refine from journal record sequences as follows:
//
//	authorized          ← presence of TypeAuthorization in the accepted prefix
//	contentReceived     ← TypeProgress payload code ProgressContentReceived
//	prepared            ← ProgressPrepared
//	contentVerified     ← ProgressVerified
//	publicationStarted  ← ProgressPublishing or FSObservation.PublicationStarted
//	published           ← FSObservation.PublicationLinearized with consistent
//	                      authorization chain (never invented from journal alone)
//	confirmationCount   ← count of TypeConfirmation (must be ≤ 1)
//
// Recover maps to the model actions Recover / RecoverAgain:
// after the first successful decision, a second Recover is effect-free at the
// stable state (Outcome.IdempotentNoop).
//
// # Residual refinement gaps (not claimed as TLC proofs of this Go code)
//
//  1. The TLA+ Recover action only lands in PUBLISHED or QUARANTINED. This kernel
//     also reconstructs CONFIRMED, CANCELLED, and IRRECOVERABLE per the
//     transaction specification and IP-S-0003 rules.
//  2. Crash in TLA+ is enabled only from a subset of states with recoveryCount=0;
//     the Go kernel may enter RECOVERING from any non-terminal durable prefix,
//     torn tail, or incomplete publication sentinel.
//  3. Progress payload codes and authorization payload layout are M1 conventions
//     for conformance tests; they are not encoded in the TLA+ model.
//  4. TLC checking of formal/transaction does not prove this implementation;
//     model-conformance tests document the mapping above without asserting
//     formal equivalence.
//  5. J-APPEND-PRE/MID/POST and J-META-POST are exercised via journal.CrashSegment
//     FailAt on FileSegment with Recover round-trip; recovery-side P-* labels are
//     exercised via FilePersist FailAt during Recover (cleanup/quarantine/confirm);
//     apply-side FilePublisher covers stage→sync→rename→dirsync FailAt with
//     Observation→Recover; OS SIGKILL at J-* and P-STAGE/P-PUBLISH labels is
//     exercised via cmd/integris-crash-stub (KillAt; mode=journal|publish).
//     Power-fail / unflushed-page simulation remains open.
//
// EVD-RECOVERY-001 / EVD-TXN-001 remain planned until evidence artifacts exist.
package recovery
