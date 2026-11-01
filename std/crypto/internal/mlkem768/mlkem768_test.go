// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mlkem768

import (
	"bytes"
	"encoding/hex"
	"flag"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestRoundTrip(t *testing.T) {
	dk, err := GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	Ke, c := ek.Encapsulate()
	Kd, err := dk.Decapsulate(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke, Kd) {
		t.Fail()
	}

	ek1, err := NewEncapsulationKey768(ek.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ek.Bytes(), ek1.Bytes()) {
		t.Fail()
	}
	dk1, err := NewDecapsulationKey768(dk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dk.Bytes(), dk1.Bytes()) {
		t.Fail()
	}
	if !bytes.Equal(TestingOnlyExpandedBytes768(dk), TestingOnlyExpandedBytes768(dk1)) {
		t.Fail()
	}
	dk2, err := TestingOnlyNewDecapsulationKey768(TestingOnlyExpandedBytes768(dk))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(TestingOnlyExpandedBytes768(dk), TestingOnlyExpandedBytes768(dk2)) {
		t.Fail()
	}
	Kd1, err := dk1.Decapsulate(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke, Kd1) {
		t.Fail()
	}

	dk3, err := GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dk.EncapsulationKey().Bytes(), dk3.EncapsulationKey().Bytes()) {
		t.Fail()
	}
	Ke1, c1 := ek.Encapsulate()
	if bytes.Equal(c, c1) || bytes.Equal(Ke, Ke1) {
		t.Fail()
	}
}

func TestBadLengths(t *testing.T) {
	dk, err := GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	ekBytes := ek.Bytes()
	_, c := ek.Encapsulate()

	for i := 0; i < len(dk.Bytes())-1; i++ {
		if _, err := NewDecapsulationKey768(dk.Bytes()[:i]); err == nil {
			t.Errorf("expected error for dk length %d", i)
		}
	}
	dkLong := append(dk.Bytes(), 0)
	if _, err := NewDecapsulationKey768(dkLong); err == nil {
		t.Errorf("expected error for dk length %d", len(dkLong))
	}

	for i := 0; i < len(ekBytes)-1; i++ {
		if _, err := NewEncapsulationKey768(ekBytes[:i]); err == nil {
			t.Errorf("expected error for ek length %d", i)
		}
	}
	ekLong := append(ekBytes, 0)
	if _, err := NewEncapsulationKey768(ekLong); err == nil {
		t.Errorf("expected error for ek length %d", len(ekLong))
	}

	for i := 0; i < len(c)-1; i++ {
		if _, err := dk.Decapsulate(c[:i]); err == nil {
			t.Errorf("expected error for c length %d", i)
		}
	}
	cLong := append(c, 0)
	if _, err := dk.Decapsulate(cLong); err == nil {
		t.Errorf("expected error for c length %d", len(cLong))
	}
}

func TestUnreducedEncapsulationKey(t *testing.T) {
	dk, err := GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey().Bytes()
	// Set the first coefficient to q, which is not reduced.
	ek[0] = byte(q & 0xff)
	ek[1] = ek[1]&0xf0 | byte(q>>8)
	if _, err := NewEncapsulationKey768(ek); err == nil {
		t.Error("expected error for unreduced encapsulation key")
	}
}

var millionFlag = flag.Bool("million", false, "run the million vector test")

// TestAccumulated accumulates 10k (or 100, or 1M) random vectors and checks the
// hash of the result, to avoid checking in 150MB of test vectors. The expected
// values are the ones used by Go's crypto/mlkem tests.
func TestAccumulated(t *testing.T) {
	n := 10000
	expected := "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc"
	if testing.Short() {
		n = 100
		expected = "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415"
	}
	if *millionFlag {
		n = 1000000
		expected = "424bf8f0e8ae99b78d788a6e2e8e9cdaf9773fc0c08a6f433507cb559edfd0f0"
	}

	s := sha3.NewShake128()
	o := sha3.NewShake128()
	seed := make([]byte, SeedSize)
	var msg [32]byte
	ct1 := make([]byte, CiphertextSize768)

	for i := 0; i < n; i++ {
		s.Read(seed)
		dk, err := NewDecapsulationKey768(seed)
		if err != nil {
			t.Fatal(err)
		}
		ek := dk.EncapsulationKey()
		o.Write(ek.Bytes())

		s.Read(msg[:])
		k, ct := ek.EncapsulateInternal(&msg)
		o.Write(ct)
		o.Write(k)

		kk, err := dk.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(kk, k) {
			t.Errorf("k: got %x, expected %x", kk, k)
		}

		s.Read(ct1)
		k1, err := dk.Decapsulate(ct1)
		if err != nil {
			t.Fatal(err)
		}
		o.Write(k1)
	}

	sum := make([]byte, 32)
	o.Read(sum)
	got := hex.EncodeToString(sum)
	if got != expected {
		t.Errorf("got %s, expected %s", got, expected)
	}
}
