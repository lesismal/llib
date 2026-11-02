// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpke

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"testing"

	"golang.org/x/crypto/sha3"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func drawRandomInput(t *testing.T, r io.Reader) []byte {
	t.Helper()
	l := make([]byte, 1)
	if _, err := r.Read(l); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, int(l[0]))
	if _, err := r.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVectors checks the RFC 9180 test vectors for DHKEM(X25519), using the
// accumulated values computed by the Go standard library's crypto/hpke tests.
func TestVectors(t *testing.T) {
	vectorsJSON, err := ioutil.ReadFile("testdata/rfc9180.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Mode           uint16 `json:"mode"`
		KEM            uint16 `json:"kem_id"`
		KDF            uint16 `json:"kdf_id"`
		AEAD           uint16 `json:"aead_id"`
		Info           string `json:"info"`
		IkmE           string `json:"ikmE"`
		IkmR           string `json:"ikmR"`
		SkRm           string `json:"skRm"`
		PkRm           string `json:"pkRm"`
		Enc            string `json:"enc"`
		AccEncryptions string `json:"encryptions_accumulated"`
		AccExports     string `json:"exports_accumulated"`
	}
	if err := json.Unmarshal(vectorsJSON, &vectors); err != nil {
		t.Fatal(err)
	}

	tested := 0
	for _, v := range vectors {
		v := v
		name := fmt.Sprintf("mode %04x kem %04x kdf %04x aead %04x", v.Mode, v.KEM, v.KDF, v.AEAD)
		t.Run(name, func(t *testing.T) {
			if v.Mode != 0 || !SupportedKEM(v.KEM) {
				t.Skip("unsupported mode or KEM")
			}
			tested++

			skR, pkR, err := DeriveKeyPair(mustDecodeHex(t, v.IkmR))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pkR, mustDecodeHex(t, v.PkRm)) {
				t.Errorf("derived public key %x, want %s", pkR, v.PkRm)
			}
			if !bytes.Equal(skR, mustDecodeHex(t, v.SkRm)) {
				t.Errorf("derived private key %x, want %s", skR, v.SkRm)
			}

			info := mustDecodeHex(t, v.Info)
			enc, sender, err := SetupSenderDeterministic(v.KEM, v.KDF, v.AEAD, pkR, info, mustDecodeHex(t, v.IkmE))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(enc, mustDecodeHex(t, v.Enc)) {
				t.Errorf("encapsulated key %x, want %s", enc, v.Enc)
			}
			recipient, err := SetupRecipient(v.KEM, v.KDF, v.AEAD, skR, enc, info)
			if err != nil {
				t.Fatal(err)
			}

			if v.AEAD == AEAD_ExportOnly {
				if _, err := sender.Seal(nil, nil); err == nil {
					t.Error("Seal with export-only AEAD succeeded")
				}
				if _, err := recipient.Open(nil, nil); err == nil {
					t.Error("Open with export-only AEAD succeeded")
				}
			} else {
				source, sink := sha3.NewShake128(), sha3.NewShake128()
				for i := 0; i < 1000; i++ {
					aad, plaintext := drawRandomInput(t, source), drawRandomInput(t, source)
					ciphertext, err := sender.Seal(aad, plaintext)
					if err != nil {
						t.Fatal(err)
					}
					sink.Write(ciphertext)
					got, err := recipient.Open(aad, ciphertext)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, plaintext) {
						t.Fatalf("Open returned %x, want %x", got, plaintext)
					}
				}
				acc := make([]byte, 16)
				sink.Read(acc)
				if !bytes.Equal(acc, mustDecodeHex(t, v.AccEncryptions)) {
					t.Errorf("accumulated encryptions %x, want %s", acc, v.AccEncryptions)
				}
			}

			source, sink := sha3.NewShake128(), sha3.NewShake128()
			for l := 0; l < 1000; l++ {
				context := drawRandomInput(t, source)
				value, err := sender.Export(context, l)
				if err != nil {
					t.Fatal(err)
				}
				sink.Write(value)
				got, err := recipient.Export(context, l)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, value) {
					t.Fatalf("recipient exported %x, want %x", got, value)
				}
			}
			acc := make([]byte, 16)
			sink.Read(acc)
			if !bytes.Equal(acc, mustDecodeHex(t, v.AccExports)) {
				t.Errorf("accumulated exports %x, want %s", acc, v.AccExports)
			}
		})
	}
	if tested == 0 {
		t.Fatal("no test vectors were checked")
	}
}

func TestRoundTripAndTampering(t *testing.T) {
	skR, pkR, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	info := []byte("tls ech\x00config")
	for _, aead := range []uint16{AEAD_AES128GCM, AEAD_AES256GCM, AEAD_ChaCha20Poly1305} {
		enc, sender, err := SetupSender(DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, aead, pkR, info, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		recipient, err := SetupRecipient(DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, aead, skR, enc, info)
		if err != nil {
			t.Fatal(err)
		}
		ct, err := sender.Seal([]byte("aad"), []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		bad := append([]byte{}, ct...)
		bad[0] ^= 1
		if _, err := recipient.Open([]byte("aad"), bad); err == nil {
			t.Errorf("aead %04x: tampered ciphertext opened", aead)
		}
		// A failed Open must not advance the sequence number.
		if pt, err := recipient.Open([]byte("aad"), ct); err != nil || string(pt) != "hello" {
			t.Errorf("aead %04x: Open = %q, %v", aead, pt, err)
		}
		if _, err := SetupRecipient(DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, aead, skR, make([]byte, X25519KeySize), info); err == nil {
			t.Errorf("aead %04x: low order encapsulated key accepted", aead)
		}
	}
	if _, _, err := SetupSender(DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, 0x1234, pkR, info, rand.Reader); err == nil {
		t.Error("unsupported AEAD accepted")
	}
}
