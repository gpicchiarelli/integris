// Package codec provides bounded canonical encoders and decoders for Integris
// on-disk formats. Multi-byte integers are little-endian. Lengths are validated
// before allocation. Digests for journal commitments are provisional SHA-256
// per IP-F-0001 pending IP-C ratification.
package codec
