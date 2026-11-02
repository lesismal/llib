//go:build go1.26
// +build go1.26

package interoptest

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"

	ltls "github.com/lesismal/llib/std/crypto/tls"
	"golang.org/x/crypto/cryptobyte"
)

const echPublicName = "public.example.test"

// echKey is an X25519 ECH key with its ECHConfig.
type echKey struct {
	config []byte // ECHConfig
	priv   []byte
}

// newECHKey generates an ECHConfig (RFC 9849, Section 4) for an X25519 key,
// offering the given KDF/AEAD pairs (HPKE identifiers).
func newECHKey(t *testing.T, configID uint8, suites ...[2]uint16) echKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(suites) == 0 {
		suites = [][2]uint16{{0x0001, 0x0001}} // HKDF-SHA256, AES-128-GCM
	}
	var b cryptobyte.Builder
	b.AddUint16(0xfe0d) // version
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(configID)
		b.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(priv.PublicKey().Bytes())
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, s := range suites {
				b.AddUint16(s[0])
				b.AddUint16(s[1])
			}
		})
		b.AddUint8(32) // maximum_name_length
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(echPublicName))
		})
		b.AddUint16(0) // extensions
	})
	return echKey{config: b.BytesOrPanic(), priv: priv.Bytes()}
}

// echConfigList serializes an ECHConfigList.
func echConfigList(keys ...echKey) []byte {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, k := range keys {
			b.AddBytes(k.config)
		}
	})
	return b.BytesOrPanic()
}

func stdECHKeys(retry bool, keys ...echKey) []stdtls.EncryptedClientHelloKey {
	var out []stdtls.EncryptedClientHelloKey
	for _, k := range keys {
		out = append(out, stdtls.EncryptedClientHelloKey{Config: k.config, PrivateKey: k.priv, SendAsRetry: retry})
	}
	return out
}

func llibECHKeys(retry bool, keys ...echKey) []ltls.EncryptedClientHelloKey {
	var out []ltls.EncryptedClientHelloKey
	for _, k := range keys {
		out = append(out, ltls.EncryptedClientHelloKey{Config: k.config, PrivateKey: k.priv, SendAsRetry: retry})
	}
	return out
}

// ---------- llib client -> stdlib server ----------

func TestECHClientAccepted(t *testing.T) {
	p := newPKI(t)
	suites := [][2]uint16{
		{0x0001, 0x0001}, // HKDF-SHA256, AES-128-GCM
		{0x0001, 0x0002}, // HKDF-SHA256, AES-256-GCM
		{0x0001, 0x0003}, // HKDF-SHA256, ChaCha20Poly1305
		{0x0002, 0x0001}, // HKDF-SHA384, AES-128-GCM
		{0x0003, 0x0003}, // HKDF-SHA512, ChaCha20Poly1305
	}
	for _, s := range suites {
		k := newECHKey(t, 7, s)
		ln := listen(t)
		ch := serveStd(ln, &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()},
			EncryptedClientHelloKeys: stdECHKeys(false, k)})
		cs, err := llibClient(ln, &ltls.Config{RootCAs: p.pool, ServerName: "example.test",
			EncryptedClientHelloConfigList: echConfigList(k)})
		r := <-ch
		if err != nil || r.err != nil {
			t.Fatalf("suite %04x/%04x: client err=%v server err=%v", s[0], s[1], err, r.err)
		}
		if !cs.ECHAccepted || !r.state.ECHAccepted {
			t.Fatalf("suite %04x/%04x: ECH not accepted: client %v server %v", s[0], s[1], cs.ECHAccepted, r.state.ECHAccepted)
		}
		// The server must have seen the inner, private server name.
		if r.chi.ServerName != "example.test" || cs.ServerName != "example.test" {
			t.Fatalf("server name: server saw %q, client reports %q", r.chi.ServerName, cs.ServerName)
		}
	}
}

// TestECHClientOuterHello checks that the outer ClientHello on the wire only
// carries the public name, not the private server name.
func TestECHClientOuterHello(t *testing.T) {
	k := newECHKey(t, 1)
	ln := listen(t)
	helloCh := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			helloCh <- nil
			return
		}
		defer c.Close()
		buf := make([]byte, 8192)
		n, _ := c.Read(buf)
		helloCh <- buf[:n]
	}()
	c, err := ltls.Dial("tcp", ln.Addr().String(), &ltls.Config{InsecureSkipVerify: true, ServerName: "secret.example.test",
		EncryptedClientHelloConfigList: echConfigList(k)})
	if err == nil {
		c.Close()
	}
	hello := <-helloCh
	if bytes.Contains(hello, []byte("secret.example.test")) {
		t.Error("private server name sent in the clear")
	}
	if !bytes.Contains(hello, []byte(echPublicName)) {
		t.Error("public name missing from the outer ClientHello")
	}
	if !bytes.Contains(hello, []byte{0xfe, 0x0d}) {
		t.Error("encrypted_client_hello extension missing")
	}
}

func TestECHClientRejected(t *testing.T) {
	p := newPKI(t)
	stale := newECHKey(t, 1)
	current := newECHKey(t, 2)

	// The server only knows a newer key: it rejects ECH, authenticates as the
	// public name and sends the new config for retries.
	ln := listen(t)
	ch := serveStd(ln, &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()},
		EncryptedClientHelloKeys: stdECHKeys(true, current)})
	_, err := llibClient(ln, &ltls.Config{RootCAs: p.pool, ServerName: "example.test",
		EncryptedClientHelloConfigList: echConfigList(stale)})
	<-ch
	var rej *ltls.ECHRejectionError
	if !errors.As(err, &rej) {
		t.Fatalf("got %v, want ECHRejectionError", err)
	}
	if !bytes.Equal(rej.RetryConfigList, echConfigList(current)) {
		t.Fatalf("retry configs %x, want %x", rej.RetryConfigList, echConfigList(current))
	}

	// Retrying with the provided configs succeeds.
	ln = listen(t)
	ch = serveStd(ln, &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()},
		EncryptedClientHelloKeys: stdECHKeys(true, current)})
	cs, err := llibClient(ln, &ltls.Config{RootCAs: p.pool, ServerName: "example.test",
		EncryptedClientHelloConfigList: rej.RetryConfigList})
	r := <-ch
	if err != nil || r.err != nil || !cs.ECHAccepted {
		t.Fatalf("retry: client err=%v server err=%v accepted=%v", err, r.err, cs.ECHAccepted)
	}

	// A server without ECH keys rejects it without retry configs.
	ln = listen(t)
	ch = serveStd(ln, &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()}})
	_, err = llibClient(ln, &ltls.Config{RootCAs: p.pool, ServerName: "example.test",
		EncryptedClientHelloConfigList: echConfigList(stale)})
	<-ch
	if !errors.As(err, &rej) || rej.RetryConfigList != nil {
		t.Fatalf("got %v (%#v), want ECHRejectionError without retry configs", err, rej)
	}
}

func TestECHClientRejectedBadPublicCert(t *testing.T) {
	p := newPKI(t)
	k := newECHKey(t, 1)
	// When ECH is rejected, the server must still authenticate as the public
	// name, so that a network attacker can't make the client accept forged
	// retry configs: with untrusted roots, the client fails the handshake
	// with a certificate error instead of an ECHRejectionError.
	ln := listen(t)
	ch := serveStd(ln, &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()}})
	_, err := llibClient(ln, &ltls.Config{RootCAs: x509.NewCertPool(), ServerName: "example.test",
		EncryptedClientHelloConfigList: echConfigList(k)})
	<-ch
	var rej *ltls.ECHRejectionError
	if err == nil || errors.As(err, &rej) {
		t.Fatalf("got %v, want a certificate verification error", err)
	}
}

func TestECHClientHRR(t *testing.T) {
	p := newPKI(t)
	k := newECHKey(t, 3)
	ln := listen(t)
	// The client sends an X25519 share, the server only accepts P-384.
	ch := serveStd(ln, &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()},
		CurvePreferences:         []stdtls.CurveID{stdtls.CurveP384},
		EncryptedClientHelloKeys: stdECHKeys(false, k)})
	cs, err := llibClient(ln, &ltls.Config{RootCAs: p.pool, ServerName: "example.test",
		CurvePreferences:               []ltls.CurveID{ltls.X25519, ltls.CurveP384},
		EncryptedClientHelloConfigList: echConfigList(k)})
	r := <-ch
	if err != nil || r.err != nil {
		t.Fatalf("client err=%v server err=%v", err, r.err)
	}
	if !cs.ECHAccepted || !r.state.ECHAccepted || !r.state.HelloRetryRequest || r.state.CurveID != stdtls.CurveP384 {
		t.Fatalf("accepted %v/%v hrr %v curve %v", cs.ECHAccepted, r.state.ECHAccepted, r.state.HelloRetryRequest, r.state.CurveID)
	}
}

func TestECHClientResumptionAndClientAuth(t *testing.T) {
	p := newPKI(t)
	k := newECHKey(t, 4)
	// serveStd clones the config for every connection: a fixed ticket key
	// lets the clones decrypt each other's tickets.
	scfg := &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()},
		ClientAuth: stdtls.RequireAndVerifyClientCert, ClientCAs: p.pool,
		SessionTicketKey:         [32]byte{1},
		EncryptedClientHelloKeys: stdECHKeys(false, k)}
	ccfg := &ltls.Config{RootCAs: p.pool, ServerName: "example.test",
		Certificates:                   []ltls.Certificate{{Certificate: [][]byte{p.cliDER, p.interDER}, PrivateKey: p.cliKey}},
		ClientSessionCache:             ltls.NewLRUClientSessionCache(4),
		EncryptedClientHelloConfigList: echConfigList(k)}
	for i := 0; i < 2; i++ {
		ln := listen(t)
		ch := serveStd(ln, scfg)
		cs, err := llibClient(ln, ccfg)
		r := <-ch
		if err != nil || r.err != nil {
			t.Fatalf("conn %d: client err=%v server err=%v", i, err, r.err)
		}
		if !cs.ECHAccepted || (i == 1) != cs.DidResume {
			t.Fatalf("conn %d: accepted %v resumed %v", i, cs.ECHAccepted, cs.DidResume)
		}
		if i == 0 && len(r.state.PeerCertificates) != 2 {
			t.Fatalf("server saw %d client certificates", len(r.state.PeerCertificates))
		}
	}
}

func TestECHClientConfigErrors(t *testing.T) {
	k := newECHKey(t, 1)
	for name, cfg := range map[string]*ltls.Config{
		"TLS 1.2 max": {InsecureSkipVerify: true, MaxVersion: ltls.VersionTLS12, EncryptedClientHelloConfigList: echConfigList(k)},
		"TLS 1.2 min": {InsecureSkipVerify: true, MinVersion: ltls.VersionTLS12, EncryptedClientHelloConfigList: echConfigList(k)},
		"malformed":   {InsecureSkipVerify: true, EncryptedClientHelloConfigList: []byte{0, 5, 1}},
		"unsupported": {InsecureSkipVerify: true, EncryptedClientHelloConfigList: echConfigList(newECHKey(t, 1, [2]uint16{0x0001, 0xffff}))},
	} {
		ln := listen(t)
		go func(ln net.Listener) {
			if c, err := ln.Accept(); err == nil {
				c.Close()
			}
		}(ln)
		if _, err := llibClient(ln, cfg); err == nil {
			t.Errorf("%s: handshake succeeded", name)
		}
	}
}

// ---------- stdlib client -> llib server ----------

func TestECHServerAccepted(t *testing.T) {
	p := newPKI(t)
	suites := [][2]uint16{
		{0x0001, 0x0001}, // HKDF-SHA256, AES-128-GCM
		{0x0001, 0x0003}, // HKDF-SHA256, ChaCha20Poly1305
		{0x0003, 0x0002}, // HKDF-SHA512, AES-256-GCM
	}
	for _, m := range modes {
		for _, s := range suites {
			k := newECHKey(t, 9, s)
			ln := listen(t)
			ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()},
				EncryptedClientHelloKeys: llibECHKeys(false, k)}, m.nonBlock)
			st, err := stdClient(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test",
				EncryptedClientHelloConfigList: echConfigList(k)})
			r := <-ch
			if err != nil || r.err != nil {
				t.Fatalf("%s %04x/%04x: client err=%v server err=%v", m.name, s[0], s[1], err, r.err)
			}
			if !st.ECHAccepted || !r.state.ECHAccepted || r.state.ServerName != "example.test" {
				t.Fatalf("%s %04x/%04x: accepted %v/%v server name %q", m.name, s[0], s[1], st.ECHAccepted, r.state.ECHAccepted, r.state.ServerName)
			}
		}
	}
}

func TestECHServerRejected(t *testing.T) {
	p := newPKI(t)
	stale := newECHKey(t, 1)
	current := newECHKey(t, 2)
	for _, m := range modes {
		// A config the server doesn't know: rejected, with retry configs.
		ln := listen(t)
		ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()},
			EncryptedClientHelloKeys: llibECHKeys(true, current)}, m.nonBlock)
		_, err := stdClient(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test",
			EncryptedClientHelloConfigList: echConfigList(stale)})
		<-ch
		var rej *stdtls.ECHRejectionError
		if !errors.As(err, &rej) || !bytes.Equal(rej.RetryConfigList, echConfigList(current)) {
			t.Fatalf("%s: got %v, want ECHRejectionError with the current config", m.name, err)
		}

		// Without ECH keys, the server ignores ECH and sends no retry configs.
		ln = listen(t)
		ch = serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}}, m.nonBlock)
		_, err = stdClient(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test",
			EncryptedClientHelloConfigList: echConfigList(stale)})
		<-ch
		if !errors.As(err, &rej) || rej.RetryConfigList != nil {
			t.Fatalf("%s: got %v, want ECHRejectionError without retry configs", m.name, err)
		}

		// Clients not offering ECH are unaffected by the server's ECH keys.
		ln = listen(t)
		ch = serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()},
			EncryptedClientHelloKeys: llibECHKeys(true, current)}, m.nonBlock)
		st, err := stdClient(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test"})
		r := <-ch
		if err != nil || r.err != nil || st.ECHAccepted {
			t.Fatalf("%s: plain client: err=%v/%v accepted=%v", m.name, err, r.err, st.ECHAccepted)
		}
	}
}

func TestECHServerHRR(t *testing.T) {
	p := newPKI(t)
	k := newECHKey(t, 5)
	for _, m := range modes {
		ln := listen(t)
		ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()},
			CurvePreferences:         []ltls.CurveID{ltls.CurveP384},
			EncryptedClientHelloKeys: llibECHKeys(false, k)}, m.nonBlock)
		st, err := stdClient(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test",
			CurvePreferences:               []stdtls.CurveID{stdtls.X25519, stdtls.CurveP384},
			EncryptedClientHelloConfigList: echConfigList(k)})
		r := <-ch
		if err != nil || r.err != nil {
			t.Fatalf("%s: client err=%v server err=%v", m.name, err, r.err)
		}
		if !st.ECHAccepted || !r.state.ECHAccepted || !st.HelloRetryRequest || st.CurveID != stdtls.CurveP384 {
			t.Fatalf("%s: accepted %v/%v hrr %v curve %v", m.name, st.ECHAccepted, r.state.ECHAccepted, st.HelloRetryRequest, st.CurveID)
		}
	}
}

func TestECHServerResumptionAndClientAuth(t *testing.T) {
	p := newPKI(t)
	k := newECHKey(t, 6)
	for _, m := range modes {
		scfg := &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()},
			ClientAuth: ltls.RequireAndVerifyClientCert, ClientCAs: p.pool,
			EncryptedClientHelloKeys: llibECHKeys(false, k)}
		ccfg := &stdtls.Config{RootCAs: p.pool, ServerName: "example.test",
			Certificates:                   []stdtls.Certificate{{Certificate: [][]byte{p.cliDER, p.interDER}, PrivateKey: p.cliKey}},
			ClientSessionCache:             stdtls.NewLRUClientSessionCache(4),
			EncryptedClientHelloConfigList: echConfigList(k)}
		for i := 0; i < 2; i++ {
			ln := listen(t)
			ch := serveLlib(t, ln, scfg, m.nonBlock)
			st, err := stdClient(ln, ccfg)
			r := <-ch
			if err != nil || r.err != nil {
				t.Fatalf("%s conn %d: client err=%v server err=%v", m.name, i, err, r.err)
			}
			if !st.ECHAccepted || !r.state.ECHAccepted || (i == 1) != st.DidResume {
				t.Fatalf("%s conn %d: accepted %v/%v resumed %v", m.name, i, st.ECHAccepted, r.state.ECHAccepted, st.DidResume)
			}
			if len(r.state.VerifiedChains) == 0 {
				t.Fatalf("%s conn %d: client certificate not verified", m.name, i)
			}
		}
	}
}

func TestECHServerGetKeys(t *testing.T) {
	p := newPKI(t)
	k := newECHKey(t, 8)
	var calls int
	ln := listen(t)
	ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()},
		// The static keys are ignored when GetEncryptedClientHelloKeys is set.
		EncryptedClientHelloKeys: llibECHKeys(false, newECHKey(t, 1)),
		GetEncryptedClientHelloKeys: func(chi *ltls.ClientHelloInfo) ([]ltls.EncryptedClientHelloKey, error) {
			calls++
			return llibECHKeys(false, k), nil
		}}, false)
	st, err := stdClient(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test",
		EncryptedClientHelloConfigList: echConfigList(k)})
	r := <-ch
	if err != nil || r.err != nil || !st.ECHAccepted || calls != 1 {
		t.Fatalf("err=%v/%v accepted=%v calls=%d", err, r.err, st.ECHAccepted, calls)
	}
}

// ---------- llib client -> llib server ----------

func TestECHLlibToLlib(t *testing.T) {
	p := newPKI(t)
	k := newECHKey(t, 10)
	for _, m := range modes {
		for _, hrr := range []bool{false, true} {
			scfg := &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()},
				EncryptedClientHelloKeys: llibECHKeys(false, k)}
			ccfg := &ltls.Config{RootCAs: p.pool, ServerName: "example.test",
				EncryptedClientHelloConfigList: echConfigList(k)}
			if hrr {
				scfg.CurvePreferences = []ltls.CurveID{ltls.CurveP384}
				ccfg.CurvePreferences = []ltls.CurveID{ltls.X25519, ltls.CurveP384}
			}
			ln := listen(t)
			ch := serveLlib(t, ln, scfg, m.nonBlock)
			cs, err := llibClient(ln, ccfg)
			r := <-ch
			if err != nil || r.err != nil {
				t.Fatalf("%s hrr=%v: client err=%v server err=%v", m.name, hrr, err, r.err)
			}
			if !cs.ECHAccepted || !r.state.ECHAccepted || r.state.ServerName != "example.test" {
				t.Fatalf("%s hrr=%v: accepted %v/%v server name %q", m.name, hrr, cs.ECHAccepted, r.state.ECHAccepted, r.state.ServerName)
			}
		}
	}
}
