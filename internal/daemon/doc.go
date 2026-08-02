// Package daemon implements privilege-separated receive for Integris:
// M2a–M2h engineering increments through the full eight-role receive chain
// (auth, parser, plan, index, apply, journal, audit, net) under a supervisor
// parent. Default serve is M2h (index owns readonly destination Scan at commit).
//
// This is an engineering preview, not release PKI or IC-1 exit. See
// docs/daemon-m2a.md.
package daemon
