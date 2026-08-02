// Package remotesync implements authenticated unidirectional push of a local
// directory tree over TCP (M1c) with chunked, resumable file transfer (M1d).
//
// Transport uses the IP-P-0001 frame codec, provisional mutual peer-auth,
// archive-auth, and ChaCha20-Poly1305 traffic keys (IP-C-0002). Shared root key
// material is required (PSK). This is not a release PKI claim and not the
// privilege-separated daemon.
//
// Files are sent as FileBegin / FileAck / FileChunk / FileEnd application
// messages. Partials live under destination/.integris/recv-partial/; completed
// trees stage under recv-stage/ then apply via internal/localsync.
//
// See docs/remotesync.md.
package remotesync
