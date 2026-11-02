// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hpke implements the base mode of Hybrid Public Key Encryption
// (RFC 9180) with DHKEM(X25519, HKDF-SHA256), as needed by Encrypted Client
// Hello. It is written for Go 1.16 on top of golang.org/x/crypto.
package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// KEM, KDF and AEAD identifiers from the IANA HPKE registry.
const (
	DHKEM_X25519_HKDF_SHA256 uint16 = 0x0020

	KDF_HKDF_SHA256 uint16 = 0x0001
	KDF_HKDF_SHA384 uint16 = 0x0002
	KDF_HKDF_SHA512 uint16 = 0x0003

	AEAD_AES128GCM        uint16 = 0x0001
	AEAD_AES256GCM        uint16 = 0x0002
	AEAD_ChaCha20Poly1305 uint16 = 0x0003
	AEAD_ExportOnly       uint16 = 0xffff
)

// X25519KeySize is the size of X25519 private keys, public keys and
// encapsulated keys.
const X25519KeySize = 32

var errUnsupported = errors.New("hpke: unsupported algorithm")

func kdfHash(id uint16) func() hash.Hash {
	switch id {
	case KDF_HKDF_SHA256:
		return sha256.New
	case KDF_HKDF_SHA384:
		return sha512.New384
	case KDF_HKDF_SHA512:
		return sha512.New
	}
	return nil
}

// aeadKeySize returns the key size of the AEAD, or 0 if it's unsupported.
// AEAD_ExportOnly has no key and is reported with -1.
func aeadKeySize(id uint16) int {
	switch id {
	case AEAD_AES128GCM:
		return 16
	case AEAD_AES256GCM, AEAD_ChaCha20Poly1305:
		return 32
	case AEAD_ExportOnly:
		return -1
	}
	return 0
}

// SupportedKEM reports whether the KEM is implemented.
func SupportedKEM(id uint16) bool { return id == DHKEM_X25519_HKDF_SHA256 }

// SupportedKDF reports whether the KDF is implemented.
func SupportedKDF(id uint16) bool { return kdfHash(id) != nil }

// SupportedAEAD reports whether the AEAD is implemented and can seal and
// open messages (the export-only AEAD can't).
func SupportedAEAD(id uint16) bool { return aeadKeySize(id) > 0 }

func labeledExtract(h func() hash.Hash, suiteID []byte, salt []byte, label string, ikm []byte) []byte {
	labeled := make([]byte, 0, 7+len(suiteID)+len(label)+len(ikm))
	labeled = append(labeled, "HPKE-v1"...)
	labeled = append(labeled, suiteID...)
	labeled = append(labeled, label...)
	labeled = append(labeled, ikm...)
	return hkdf.Extract(h, labeled, salt)
}

func labeledExpand(h func() hash.Hash, suiteID []byte, prk []byte, label string, info []byte, length int) []byte {
	labeled := make([]byte, 2, 2+7+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeled, uint16(length))
	labeled = append(labeled, "HPKE-v1"...)
	labeled = append(labeled, suiteID...)
	labeled = append(labeled, label...)
	labeled = append(labeled, info...)
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(h, prk, labeled), out); err != nil {
		panic("hpke: internal error: " + err.Error())
	}
	return out
}

var kemSuiteID = []byte{'K', 'E', 'M', 0x00, 0x20}

// DeriveKeyPair derives an X25519 key pair from ikm, see RFC 9180,
// Section 7.1.3.
func DeriveKeyPair(ikm []byte) (priv, pub []byte, err error) {
	prk := labeledExtract(sha256.New, kemSuiteID, nil, "dkp_prk", ikm)
	priv = labeledExpand(sha256.New, kemSuiteID, prk, "sk", nil, X25519KeySize)
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// GenerateKeyPair generates a random X25519 key pair.
func GenerateKeyPair(rand io.Reader) (priv, pub []byte, err error) {
	priv = make([]byte, X25519KeySize)
	if _, err := io.ReadFull(rand, priv); err != nil {
		return nil, nil, err
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// PublicKey returns the X25519 public key of priv.
func PublicKey(priv []byte) ([]byte, error) {
	if len(priv) != X25519KeySize {
		return nil, errors.New("hpke: invalid X25519 private key")
	}
	return curve25519.X25519(priv, curve25519.Basepoint)
}

func extractAndExpand(dh, kemContext []byte) []byte {
	prk := labeledExtract(sha256.New, kemSuiteID, nil, "eae_prk", dh)
	return labeledExpand(sha256.New, kemSuiteID, prk, "shared_secret", kemContext, 32)
}

// encap is DHKEM Encap with the ephemeral private key skE.
func encap(pkR, skE []byte) (sharedSecret, enc []byte, err error) {
	if len(pkR) != X25519KeySize {
		return nil, nil, errors.New("hpke: invalid X25519 public key")
	}
	pkE, err := curve25519.X25519(skE, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	// curve25519.X25519 rejects low order points (an all-zero output).
	dh, err := curve25519.X25519(skE, pkR)
	if err != nil {
		return nil, nil, err
	}
	kemContext := append(append([]byte{}, pkE...), pkR...)
	return extractAndExpand(dh, kemContext), pkE, nil
}

func decap(enc, skR []byte) ([]byte, error) {
	if len(enc) != X25519KeySize {
		return nil, errors.New("hpke: invalid encapsulated key")
	}
	pkR, err := PublicKey(skR)
	if err != nil {
		return nil, err
	}
	dh, err := curve25519.X25519(skR, enc)
	if err != nil {
		return nil, err
	}
	kemContext := append(append([]byte{}, enc...), pkR...)
	return extractAndExpand(dh, kemContext), nil
}

type context struct {
	aead           cipher.AEAD
	baseNonce      []byte
	seq            uint64
	exporterSecret []byte
	kdf            func() hash.Hash
	suiteID        []byte
}

// Sender is the HPKE sender context, used to seal messages.
type Sender struct{ *context }

// Recipient is the HPKE recipient context, used to open messages.
type Recipient struct{ *context }

func newContext(sharedSecret []byte, kdfID, aeadID uint16, info []byte) (*context, error) {
	h := kdfHash(kdfID)
	keySize := aeadKeySize(aeadID)
	if h == nil || keySize == 0 {
		return nil, errUnsupported
	}
	suiteID := []byte{'H', 'P', 'K', 'E', 0x00, 0x20, byte(kdfID >> 8), byte(kdfID), byte(aeadID >> 8), byte(aeadID)}

	pskIDHash := labeledExtract(h, suiteID, nil, "psk_id_hash", nil)
	infoHash := labeledExtract(h, suiteID, nil, "info_hash", info)
	ksContext := append([]byte{0}, pskIDHash...) // mode_base
	ksContext = append(ksContext, infoHash...)
	secret := labeledExtract(h, suiteID, sharedSecret, "secret", nil)

	c := &context{
		exporterSecret: labeledExpand(h, suiteID, secret, "exp", ksContext, h().Size()),
		kdf:            h,
		suiteID:        suiteID,
	}
	if keySize < 0 {
		return c, nil // export-only
	}
	key := labeledExpand(h, suiteID, secret, "key", ksContext, keySize)
	var err error
	switch aeadID {
	case AEAD_AES128GCM, AEAD_AES256GCM:
		var block cipher.Block
		if block, err = aes.NewCipher(key); err == nil {
			c.aead, err = cipher.NewGCM(block)
		}
	case AEAD_ChaCha20Poly1305:
		c.aead, err = chacha20poly1305.New(key)
	}
	if err != nil {
		return nil, err
	}
	c.baseNonce = labeledExpand(h, suiteID, secret, "base_nonce", ksContext, c.aead.NonceSize())
	return c, nil
}

// SetupSender establishes a sender context for the recipient public key pkR,
// returning the encapsulated key to send to the recipient.
func SetupSender(kemID, kdfID, aeadID uint16, pkR, info []byte, rand io.Reader) (enc []byte, s *Sender, err error) {
	if !SupportedKEM(kemID) {
		return nil, nil, errUnsupported
	}
	skE := make([]byte, X25519KeySize)
	if _, err := io.ReadFull(rand, skE); err != nil {
		return nil, nil, err
	}
	return setupSender(kdfID, aeadID, pkR, info, skE)
}

// SetupSenderDeterministic is like SetupSender, but derives the ephemeral key
// from ikmE. It's only meant for testing against known answers.
func SetupSenderDeterministic(kemID, kdfID, aeadID uint16, pkR, info, ikmE []byte) (enc []byte, s *Sender, err error) {
	if !SupportedKEM(kemID) {
		return nil, nil, errUnsupported
	}
	skE, _, err := DeriveKeyPair(ikmE)
	if err != nil {
		return nil, nil, err
	}
	return setupSender(kdfID, aeadID, pkR, info, skE)
}

func setupSender(kdfID, aeadID uint16, pkR, info, skE []byte) ([]byte, *Sender, error) {
	sharedSecret, enc, err := encap(pkR, skE)
	if err != nil {
		return nil, nil, err
	}
	c, err := newContext(sharedSecret, kdfID, aeadID, info)
	if err != nil {
		return nil, nil, err
	}
	return enc, &Sender{c}, nil
}

// SetupRecipient establishes a recipient context for the private key skR and
// the encapsulated key enc received from the sender.
func SetupRecipient(kemID, kdfID, aeadID uint16, skR, enc, info []byte) (*Recipient, error) {
	if !SupportedKEM(kemID) {
		return nil, errUnsupported
	}
	sharedSecret, err := decap(enc, skR)
	if err != nil {
		return nil, err
	}
	c, err := newContext(sharedSecret, kdfID, aeadID, info)
	if err != nil {
		return nil, err
	}
	return &Recipient{c}, nil
}

func (c *context) nextNonce() ([]byte, error) {
	if c.seq == ^uint64(0) {
		return nil, errors.New("hpke: message limit reached")
	}
	nonce := append([]byte{}, c.baseNonce...)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], c.seq)
	for i := range seq {
		nonce[len(nonce)-8+i] ^= seq[i]
	}
	c.seq++
	return nonce, nil
}

// Seal encrypts and authenticates plaintext and authenticates aad.
func (s *Sender) Seal(aad, plaintext []byte) ([]byte, error) {
	if s.aead == nil {
		return nil, errors.New("hpke: Seal with export-only AEAD")
	}
	nonce, err := s.nextNonce()
	if err != nil {
		return nil, err
	}
	return s.aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open authenticates aad and ciphertext and decrypts ciphertext.
func (r *Recipient) Open(aad, ciphertext []byte) ([]byte, error) {
	if r.aead == nil {
		return nil, errors.New("hpke: Open with export-only AEAD")
	}
	// The sequence number only advances on success, see RFC 9180,
	// Section 5.2.
	if r.seq == ^uint64(0) {
		return nil, errors.New("hpke: message limit reached")
	}
	nonce := append([]byte{}, r.baseNonce...)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], r.seq)
	for i := range seq {
		nonce[len(nonce)-8+i] ^= seq[i]
	}
	plaintext, err := r.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	r.seq++
	return plaintext, nil
}

// Export derives a secret of the given length from the exporter secret.
func (c *context) Export(exporterContext []byte, length int) ([]byte, error) {
	if length < 0 || length > 255*c.kdf().Size() {
		return nil, errors.New("hpke: invalid export length")
	}
	return labeledExpand(c.kdf, c.suiteID, c.exporterSecret, "sec", exporterContext, length), nil
}
