//go:build go1.26
// +build go1.26

package mlkem768

import (
	"bytes"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/rand"
	"testing"
)

// TestStdlibInterop cross-checks this port against the standard library's
// crypto/mlkem when built with a toolchain that has it.
func TestStdlibInterop(t *testing.T) {
	for i := 0; i < 200; i++ {
		seed := make([]byte, SeedSize)
		rand.Read(seed)

		dk, err := NewDecapsulationKey768(seed)
		if err != nil {
			t.Fatal(err)
		}
		sdk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dk.EncapsulationKey().Bytes(), sdk.EncapsulationKey().Bytes()) {
			t.Fatal("encapsulation key mismatch")
		}

		// Derandomized encapsulation must match exactly.
		var m [32]byte
		rand.Read(m[:])
		K, c := dk.EncapsulationKey().EncapsulateInternal(&m)
		sK, sc, err := mlkemtest.Encapsulate768(sdk.EncapsulationKey(), m[:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(K, sK) || !bytes.Equal(c, sc) {
			t.Fatal("derandomized encapsulation mismatch")
		}

		// stdlib encapsulates, we decapsulate.
		sK, sc = sdk.EncapsulationKey().Encapsulate()
		K, err = dk.Decapsulate(sc)
		if err != nil || !bytes.Equal(K, sK) {
			t.Fatal("decapsulation of stdlib ciphertext failed")
		}

		// We encapsulate, stdlib decapsulates.
		ek, err := NewEncapsulationKey768(sdk.EncapsulationKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		K, c = ek.Encapsulate()
		sK, err = sdk.Decapsulate(c)
		if err != nil || !bytes.Equal(K, sK) {
			t.Fatal("stdlib decapsulation of our ciphertext failed")
		}

		// Implicit rejection of a random ciphertext must agree.
		rand.Read(c)
		K, _ = dk.Decapsulate(c)
		sK, _ = sdk.Decapsulate(c)
		if !bytes.Equal(K, sK) {
			t.Fatal("implicit rejection mismatch")
		}
	}
}
