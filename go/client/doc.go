// Package client is a Go SDK for the MicroWAF Unix-socket API.
//
// Framing matches the org IPC convention used by wireless-programmer:
// a 4-byte little-endian uint32 length prefix followed by a UTF-8 JSON body,
// with a maximum frame size of 1 MiB.
//
// See docs/api.md for the full wire protocol reference.
package client
