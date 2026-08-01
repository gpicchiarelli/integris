// Package plan implements the deterministic canonical planner kernel (IP-S-0002).
//
// Given identical validated inputs, Build produces byte-identical plan documents
// and digests independent of map iteration, goroutine schedule, acquisition
// order, locale, and wall clock. Blocking classifications (UNREPRESENTABLE,
// UNKNOWN, POLICY_FORBIDDEN, and WRAPPED outside the allow-list) never yield an
// authorize-able plan; Preflight enumerates blockers in canonical order.
//
// Digests use codec.SHA256 (provisional per IP-F-0001). EVD-PLAN-001 remains
// planned until release evidence artifacts exist under evidence/planner/.
package plan
