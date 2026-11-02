// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"math/rand"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// TestECHParsersNoPanic feeds random and truncated input to the parsers that
// handle attacker-controlled ECH data.
func TestECHParsersNoPanic(t *testing.T) {
	outer := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		sessionId:          make([]byte, 32),
		cipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
		serverName:         "public.example",
		supportedCurves:    []CurveID{X25519},
		supportedVersions:  []uint16{VersionTLS13},
		keyShares:          []keyShare{{group: X25519, data: make([]byte, 32)}},
	}
	outer.marshal()

	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 5000; i++ {
		b := make([]byte, rnd.Intn(300))
		rnd.Read(b)
		parseECHExt(b)
		parseECHConfigList(b)
		parseECHConfig(b)
		decodeInnerClientHello(outer, b)
	}
}

func encodedInner(t *testing.T, exts func(b *cryptobyte.Builder)) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint16(VersionTLS12)
	b.AddBytes(make([]byte, 32)) // random
	b.AddUint8(0)                // empty session ID
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(TLS_AES_128_GCM_SHA256) })
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(compressionNone) })
	b.AddUint16LengthPrefixed(exts)
	return b.BytesOrPanic()
}

func TestDecodeInnerClientHello(t *testing.T) {
	outer := &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		sessionId:          []byte{1, 2, 3},
		cipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
		serverName:         "public.example",
		supportedCurves:    []CurveID{X25519},
		supportedVersions:  []uint16{VersionTLS13},
		keyShares:          []keyShare{{group: X25519, data: make([]byte, 32)}},
	}
	outer.marshal()

	echInner := func(b *cryptobyte.Builder) {
		b.AddUint16(extensionEncryptedClientHello)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(uint8(innerECHExt)) })
	}
	outerExts := func(types ...uint16) func(b *cryptobyte.Builder) {
		return func(b *cryptobyte.Builder) {
			b.AddUint16(extensionECHOuterExtensions)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, typ := range types {
						b.AddUint16(typ)
					}
				})
			})
		}
	}
	serverName := func(b *cryptobyte.Builder) {
		b.AddUint16(extensionServerName)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8(0)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("secret.example")) })
			})
		})
	}

	// A valid inner ClientHello, decompressing extensions from the outer one.
	inner, err := decodeInnerClientHello(outer, encodedInner(t, func(b *cryptobyte.Builder) {
		serverName(b)
		echInner(b)
		outerExts(extensionSupportedCurves, extensionSupportedVersions, extensionKeyShare)(b)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if inner.serverName != "secret.example" || len(inner.keyShares) != 1 ||
		!bytes.Equal(inner.sessionId, outer.sessionId) || inner.supportedVersions[0] != VersionTLS13 {
		t.Fatalf("unexpected inner ClientHello: %+v", inner)
	}

	for name, exts := range map[string]func(b *cryptobyte.Builder){
		"missing inner ECH extension": func(b *cryptobyte.Builder) {
			outerExts(extensionSupportedVersions)(b)
		},
		"outer ECH extension reference": func(b *cryptobyte.Builder) {
			echInner(b)
			outerExts(extensionEncryptedClientHello)(b)
		},
		"out of order references": func(b *cryptobyte.Builder) {
			echInner(b)
			outerExts(extensionKeyShare, extensionSupportedVersions)(b)
		},
		"duplicate references": func(b *cryptobyte.Builder) {
			echInner(b)
			outerExts(extensionSupportedVersions, extensionSupportedVersions)(b)
		},
		"missing referenced extension": func(b *cryptobyte.Builder) {
			echInner(b)
			outerExts(extensionALPN)(b)
		},
		"two outer_extensions": func(b *cryptobyte.Builder) {
			echInner(b)
			outerExts(extensionSupportedCurves)(b)
			outerExts(extensionSupportedVersions)(b)
		},
		"no TLS 1.3": func(b *cryptobyte.Builder) {
			echInner(b)
		},
	} {
		if _, err := decodeInnerClientHello(outer, encodedInner(t, exts)); err == nil {
			t.Errorf("%s: decoded successfully", name)
		}
	}

	// Non-zero padding must be rejected.
	padded := append(encodedInner(t, func(b *cryptobyte.Builder) {
		echInner(b)
		outerExts(extensionSupportedVersions)(b)
	}), 0, 0, 1)
	if _, err := decodeInnerClientHello(outer, padded); err == nil {
		t.Error("non-zero padding accepted")
	}
}

// TestECHInnerOuterRoundTrip checks that the inner ClientHello encoding used by
// the client decodes back to the same bytes on the server, which the
// transcripts of both sides depend on.
func TestECHInnerOuterRoundTrip(t *testing.T) {
	inner := &clientHelloMsg{
		vers:                             VersionTLS12,
		random:                           bytes.Repeat([]byte{1}, 32),
		sessionId:                        bytes.Repeat([]byte{2}, 32),
		cipherSuites:                     []uint16{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256},
		compressionMethods:               []uint8{compressionNone},
		serverName:                       "secret.example",
		ocspStapling:                     true,
		scts:                             true,
		supportedCurves:                  []CurveID{X25519MLKEM768, X25519, CurveP256},
		supportedSignatureAlgorithms:     supportedSignatureAlgorithms,
		supportedSignatureAlgorithmsCert: supportedSignatureAlgorithmsCert,
		alpnProtocols:                    []string{"h2", "http/1.1"},
		supportedVersions:                []uint16{VersionTLS13},
		keyShares:                        []keyShare{{group: X25519, data: bytes.Repeat([]byte{3}, 32)}},
		pskModes:                         []uint8{pskModeDHE},
		encryptedClientHello:             []byte{uint8(innerECHExt)},
	}
	outer := inner.clone()
	outer.serverName = "public.example"
	outer.random = bytes.Repeat([]byte{4}, 32)
	outer.encryptedClientHello = []byte{uint8(outerECHExt), 1, 2, 3}
	outer.unmarshal(outer.marshal())

	decoded, err := decodeInnerClientHello(outer, encodeInnerClientHello(inner, 64))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.raw, inner.marshal()) {
		t.Fatalf("decoded inner ClientHello\n%x\ndoesn't match the client's\n%x", decoded.raw, inner.marshal())
	}
}
