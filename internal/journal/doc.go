// Package journal implements an append-only, commitment-chained verifiable
// journal over a single segment. Readers accept the longest fully delimited,
// canonical, commitment-valid, strictly monotonic prefix. Torn final records
// are reported; interior corruption is fatal (IP-F-0001).
package journal
