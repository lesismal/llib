//go:build go1.26
// +build go1.26

package interoptest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	ltls "github.com/lesismal/llib/std/crypto/tls"
)

// ---------- certificates ----------

type pki struct {
	caCert, interCert, srvCert, cliCert *x509.Certificate
	caKey, interKey, srvKey, cliKey     *ecdsa.PrivateKey
	caDER, interDER, srvDER, cliDER     []byte
	pool                                *x509.CertPool
}

func mkCert(t *testing.T, tmpl, parent *x509.Certificate, pub, priv interface{}) ([]byte, *x509.Certificate) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, c
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var serial int64

func tmpl(cn string, ca bool, eku []x509.ExtKeyUsage) *x509.Certificate {
	serial++
	t := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  eku,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if ca {
		t.IsCA = true
		t.BasicConstraintsValid = true
		t.KeyUsage |= x509.KeyUsageCertSign
	}
	return t
}

func newPKI(t *testing.T) *pki {
	p := &pki{caKey: newKey(t), interKey: newKey(t), srvKey: newKey(t), cliKey: newKey(t)}
	caT := tmpl("ca", true, nil)
	p.caDER, p.caCert = mkCert(t, caT, caT, &p.caKey.PublicKey, p.caKey)
	p.interDER, p.interCert = mkCert(t, tmpl("inter", true, nil), p.caCert, &p.interKey.PublicKey, p.caKey)
	st := tmpl("server", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	st.DNSNames = []string{"example.test"}
	p.srvDER, p.srvCert = mkCert(t, st, p.caCert, &p.srvKey.PublicKey, p.caKey)
	p.cliDER, p.cliCert = mkCert(t, tmpl("client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}), p.interCert, &p.cliKey.PublicKey, p.interKey)
	p.pool = x509.NewCertPool()
	p.pool.AddCert(p.caCert)
	return p
}

func (p *pki) lServerCert() ltls.Certificate {
	return ltls.Certificate{Certificate: [][]byte{p.srvDER}, PrivateKey: p.srvKey}
}
func (p *pki) sServerCert() stdtls.Certificate {
	return stdtls.Certificate{Certificate: [][]byte{p.srvDER}, PrivateKey: p.srvKey}
}

// ---------- llib servers (blocking and non-blocking) ----------

type result struct {
	err   error
	state ltls.ConnectionState
}

// serveLlib accepts one connection and runs an echo server on it.
// In non-blocking mode, raw bytes are fed via Append in tiny chunks, which is
// how nbio drives the state machine.
func serveLlib(t *testing.T, ln net.Listener, cfg *ltls.Config, nonBlock bool) <-chan result {
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{err: panicErr{r}}
			}
		}()
		raw, err := ln.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		if !nonBlock {
			c := ltls.Server(raw, cfg)
			if err := c.Handshake(); err != nil {
				ch <- result{err: err}
				return
			}
			// Read the whole 5-byte message: TLS 1.0 clients split it 1/n-1.
			buf := make([]byte, 5)
			n, err := io.ReadFull(c, buf)
			if err == nil {
				_, err = c.Write(buf[:n])
			}
			ch <- result{err: err, state: c.ConnectionState()}
			return
		}
		c := ltls.NewConn(raw, cfg, false, true)
		rbuf := make([]byte, 7)
		out := make([]byte, 64)
		got := 0
		for {
			n, err := raw.Read(rbuf)
			if n > 0 {
				c.Append(rbuf[:n])
				m, rerr := c.Read(out[got:])
				if rerr != nil {
					ch <- result{err: rerr}
					return
				}
				// Echo once the whole 5-byte message is in: TLS 1.0
				// clients split it 1/n-1.
				if got += m; got >= 5 {
					_, werr := c.Write(out[:got])
					ch <- result{err: werr, state: c.ConnectionState()}
					return
				}
			}
			if err != nil {
				ch <- result{err: err}
				return
			}
		}
	}()
	return ch
}

type panicErr struct{ v interface{} }

func (p panicErr) Error() string { return fmt.Sprint("PANIC: ", p.v) }

func listen(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// stdClient dials ln with the stdlib client and echoes a message.
func stdClient(ln net.Listener, cfg *stdtls.Config) (stdtls.ConnectionState, error) {
	c, err := stdtls.Dial("tcp", ln.Addr().String(), cfg)
	if err != nil {
		return stdtls.ConnectionState{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("hello")); err != nil {
		return stdtls.ConnectionState{}, err
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		return stdtls.ConnectionState{}, err
	}
	if string(buf) != "hello" {
		return stdtls.ConnectionState{}, io.ErrUnexpectedEOF
	}
	return c.ConnectionState(), nil
}

var modes = []struct {
	name     string
	nonBlock bool
}{{"blocking", false}, {"nonblocking", true}}

var versions = []struct {
	name string
	v    uint16
}{{"TLS12", stdtls.VersionTLS12}, {"TLS13", stdtls.VersionTLS13}}

// ---------- tests ----------

func TestBasicAndClientCertChain(t *testing.T) {
	p := newPKI(t)
	for _, m := range modes {
		for _, v := range versions {
			t.Run(m.name+"/"+v.name, func(t *testing.T) {
				ln := listen(t)
				scfg := &ltls.Config{
					Certificates: []ltls.Certificate{p.lServerCert()},
					ClientAuth:   ltls.RequireAndVerifyClientCert,
					ClientCAs:    p.pool,
				}
				ch := serveLlib(t, ln, scfg, m.nonBlock)
				ccfg := &stdtls.Config{
					RootCAs: p.pool, ServerName: "example.test", MaxVersion: v.v,
					// leaf + intermediate: two certificates in the chain
					Certificates: []stdtls.Certificate{{Certificate: [][]byte{p.cliDER, p.interDER}, PrivateKey: p.cliKey}},
				}
				st, err := stdClient(ln, ccfg)
				r := <-ch
				if err != nil || r.err != nil {
					t.Fatalf("client err=%v server err=%v", err, r.err)
				}
				if st.Version != v.v || len(r.state.VerifiedChains) == 0 {
					t.Fatalf("unexpected state: version %x chains %d", st.Version, len(r.state.VerifiedChains))
				}
			})
		}
	}
}

func TestResumption(t *testing.T) {
	p := newPKI(t)
	for _, m := range modes {
		for _, v := range versions {
			t.Run(m.name+"/"+v.name, func(t *testing.T) {
				scfg := &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}}
				ccfg := &stdtls.Config{RootCAs: p.pool, ServerName: "example.test", MaxVersion: v.v,
					ClientSessionCache: stdtls.NewLRUClientSessionCache(4)}
				for i := 0; i < 2; i++ {
					ln := listen(t)
					ch := serveLlib(t, ln, scfg, m.nonBlock)
					st, err := stdClient(ln, ccfg)
					r := <-ch
					if err != nil || r.err != nil {
						t.Fatalf("conn %d: client err=%v server err=%v", i, err, r.err)
					}
					if i == 1 && !st.DidResume {
						t.Fatalf("second connection did not resume")
					}
				}
			})
		}
	}
}

func TestALPN(t *testing.T) {
	p := newPKI(t)
	cases := []struct {
		server, client []string
		want           string
		fail           bool
	}{
		{[]string{"h2", "http/1.1"}, []string{"http/1.1"}, "http/1.1", false},
		{[]string{"h2"}, []string{"http/1.1"}, "", false}, // http/1.1 fallback
		{[]string{"h2"}, []string{"foo"}, "", true},       // strict ALPN
		{nil, []string{"foo"}, "", false},
	}
	for _, m := range modes {
		for _, v := range versions {
			for i, c := range cases {
				ln := listen(t)
				ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}, NextProtos: c.server}, m.nonBlock)
				st, err := stdClient(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test", MaxVersion: v.v, NextProtos: c.client})
				r := <-ch
				if c.fail {
					if err == nil || r.err == nil || !strings.Contains(err.Error(), "no application protocol") {
						t.Errorf("%s/%s case %d: want failure, client err=%v server err=%v", m.name, v.name, i, err, r.err)
					}
					if r.err != nil && !strings.Contains(r.err.Error(), `"foo"`) {
						t.Errorf("server error not quoted: %v", r.err)
					}
					continue
				}
				if err != nil || r.err != nil || st.NegotiatedProtocol != c.want {
					t.Errorf("%s/%s case %d: client err=%v server err=%v proto=%q", m.name, v.name, i, err, r.err, st.NegotiatedProtocol)
				}
			}
		}
	}
}

func TestDefaults(t *testing.T) {
	p := newPKI(t)
	run := func(scfg *ltls.Config, ccfg *stdtls.Config) (error, error) {
		ln := listen(t)
		ch := serveLlib(t, ln, scfg, false)
		_, err := stdClient(ln, ccfg)
		r := <-ch
		return err, r.err
	}
	base := func() *stdtls.Config {
		return &stdtls.Config{RootCAs: p.pool, ServerName: "example.test"}
	}
	// TLS 1.1 is off by default...
	c := base()
	c.MinVersion, c.MaxVersion = stdtls.VersionTLS10, stdtls.VersionTLS11
	if ce, se := run(&ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}}, c); ce == nil || se == nil {
		t.Errorf("TLS 1.1 accepted by default: %v %v", ce, se)
	}
	// ...but can be re-enabled.
	if ce, se := run(&ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}, MinVersion: ltls.VersionTLS10}, c); ce != nil || se != nil {
		t.Errorf("TLS 1.1 with explicit MinVersion failed: %v %v", ce, se)
	}

	// RSA key exchange and 3DES are off by default: check the cipher suites
	// offered in the ClientHello of an llib client with default settings.
	helloCh := make(chan []byte, 1)
	ln := listen(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			helloCh <- nil
			return
		}
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		helloCh <- buf[:n]
		c.Close()
	}()
	lc, err := ltls.Dial("tcp", ln.Addr().String(), &ltls.Config{InsecureSkipVerify: true})
	if err == nil {
		lc.Close()
	}
	hello := <-helloCh
	for _, id := range []uint16{ltls.TLS_RSA_WITH_AES_128_GCM_SHA256, ltls.TLS_RSA_WITH_AES_128_CBC_SHA, ltls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, ltls.TLS_RSA_WITH_3DES_EDE_CBC_SHA} {
		if containsSuite(hello, id) {
			t.Errorf("default ClientHello offers %x", id)
		}
	}
	if !containsSuite(hello, ltls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
		t.Errorf("default ClientHello lost ECDHE suites")
	}
	// supported_versions must not include TLS 1.0/1.1.
	if bytes.Contains(hello, []byte{0x00, 0x2b}) {
		i := bytes.Index(hello, []byte{0x00, 0x2b})
		ext := hello[i+4 : i+4+int(hello[i+3])]
		if bytes.Contains(ext[1:], []byte{3, 1}) || bytes.Contains(ext[1:], []byte{3, 2}) {
			t.Errorf("supported_versions offers TLS 1.0/1.1: %x", ext)
		}
	}
}

// containsSuite parses the cipher suite list of a raw ClientHello record.
func containsSuite(rec []byte, id uint16) bool {
	b := rec[5+4:]      // record header + handshake header
	b = b[2+32:]        // version + random
	b = b[1+int(b[0]):] // session id
	n := int(b[0])<<8 | int(b[1])
	b = b[2 : 2+n]
	for i := 0; i+1 < len(b); i += 2 {
		if uint16(b[i])<<8|uint16(b[i+1]) == id {
			return true
		}
	}
	return false
}

// TestTicketAgeAdd checks CVE-2022-30629: ticket_age_add must be random.
func TestTicketAgeAdd(t *testing.T) {
	p := newPKI(t)
	ages := map[uint64]bool{}
	for i := 0; i < 3; i++ {
		ln := listen(t)
		ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}}, false)
		cache := &recCache{}
		c, err := ltls.Dial("tcp", ln.Addr().String(), &ltls.Config{RootCAs: p.pool, ServerName: "example.test", ClientSessionCache: cache})
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("hello"))
		buf := make([]byte, 5)
		io.ReadFull(c, buf) // tickets are processed while reading
		c.Close()
		<-ch
		if cache.cs == nil {
			t.Fatal("no session ticket received")
		}
		ages[reflect.ValueOf(cache.cs).Elem().FieldByName("ageAdd").Uint()] = true
	}
	if len(ages) < 2 || ages[0] {
		t.Errorf("ticket_age_add is not random: %v", ages)
	}
}

type recCache struct {
	mu sync.Mutex
	cs *ltls.ClientSessionState
}

func (c *recCache) Get(string) (*ltls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cs, c.cs != nil
}
func (c *recCache) Put(_ string, cs *ltls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cs = cs
}

// TestHugeClientCertNoPanic checks CVE-2022-41724: a client certificate chain
// large enough to overflow the session ticket must not panic the server.
func TestHugeClientCertNoPanic(t *testing.T) {
	p := newPKI(t)
	key := newKey(t)
	// Grow a self-signed certificate until the Certificate message is just under 64KiB.
	var der []byte
	// The Certificate message must fit in 64KiB (der+9 <= 65536) while the
	// resulting ticket must not fit in 16 bits (der > ~65417).
	for size := 65400; size > 60000; size-- {
		tm := tmpl("huge", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		tm.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: make([]byte, size)}}
		der, _ = mkCert(t, tm, tm, &key.PublicKey, key)
		// handshake body: ctx(1) + list(3) + certlen(3) + der + exts(2)
		if 1+3+3+len(der)+2 <= 65536 {
			break
		}
	}
	t.Logf("client cert size %d", len(der))
	if len(der) <= 65420 {
		t.Fatalf("certificate too small to overflow the ticket: %d", len(der))
	}
	for _, m := range modes {
		ln := listen(t)
		ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}, ClientAuth: ltls.RequestClientCert}, m.nonBlock)
		// A session cache makes the client offer psk_dhe_ke, so the server issues a ticket.
		_, cerr := stdClient(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test",
			ClientSessionCache: stdtls.NewLRUClientSessionCache(1),
			Certificates:       []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
		r := <-ch
		if _, ok := r.err.(panicErr); ok {
			t.Fatalf("%s: server panicked: %v", m.name, r.err)
		}
		t.Logf("%s: client err=%v server err=%v", m.name, cerr, r.err)
	}
}

// TestResumptionRechecksRoots checks CVE-2025-68121 (client side): a cached
// session must not be resumed once its chain is no longer trusted.
func TestResumptionRechecksRoots(t *testing.T) {
	p := newPKI(t)
	for _, v := range versions {
		cache := ltls.NewLRUClientSessionCache(4)
		scfg := &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()}}
		dial := func(roots *x509.CertPool) (bool, error) {
			ln := listen(t)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				s := stdtls.Server(c, scfg)
				s.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 5)
				if _, err := io.ReadFull(s, buf); err == nil {
					s.Write(buf)
				}
				s.Close()
			}()
			c, err := ltls.Dial("tcp", ln.Addr().String(), &ltls.Config{RootCAs: roots, ServerName: "example.test", MaxVersion: v.v, ClientSessionCache: cache})
			if err != nil {
				return false, err
			}
			defer c.Close()
			c.Write([]byte("hello"))
			buf := make([]byte, 5)
			if _, err := io.ReadFull(c, buf); err != nil {
				return false, err
			}
			return c.ConnectionState().DidResume, nil
		}
		if _, err := dial(p.pool); err != nil {
			t.Fatalf("%s: first dial: %v", v.name, err)
		}
		if resumed, err := dial(p.pool); err != nil || !resumed {
			t.Fatalf("%s: second dial should resume: resumed=%v err=%v", v.name, resumed, err)
		}
		resumed, err := dial(x509.NewCertPool())
		if err == nil || resumed {
			t.Errorf("%s: resumed with untrusted roots: resumed=%v err=%v", v.name, resumed, err)
		}
	}
}
