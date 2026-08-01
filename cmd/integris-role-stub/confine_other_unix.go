//go:build unix && !linux

package main

func applyBestEffortConfinement() {
	// Darwin/FreeBSD/OpenBSD: platform adapters deferred; no-op in engineering stub.
}
