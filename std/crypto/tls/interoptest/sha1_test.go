//go:build go1.26
// +build go1.26

//go:debug tlssha1=1

// The tlssha1=1 directive lets the stdlib peer use SHA-1 signatures again, so
// these tests check that llib itself refuses them (RFC 9155).

package interoptest

import (
	stdtls "crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"

	ltls "github.com/lesismal/llib/std/crypto/tls"
)

const (
	sigECDSASHA1 = 0x0203
	sigPKCS1SHA1 = 0x0201
)

// walkHandshake calls fn for every handshake message in the complete plaintext
// records of b, until a ChangeCipherSpec record is seen. It returns false once
// encryption has started. fn may modify body in place.
func walkHandshake(b []byte, fn func(typ byte, body []byte)) bool {
	for len(b) >= 5 {
		n := int(b[3])<<8 | int(b[4])
		if b[0] == 20 {
			return false
		}
		if b[0] == 22 {
			p := b[5 : 5+n]
			for len(p) >= 4 {
				m := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
				fn(p[0], p[4:4+m])
				p = p[4+m:]
			}
		}
		b = b[5+n:]
	}
	return true
}

// recordLen returns the length of the complete records at the start of b.
func recordLen(b []byte) int {
	i := 0
	for len(b)-i >= 5 {
		n := 5 + (int(b[i+3])<<8 | int(b[i+4]))
		if len(b)-i < n {
			break
		}
		i += n
	}
	return i
}

// rewriteConn applies fn to plaintext handshake messages read from (in) or
// written to (out) the wrapped connection.
type rewriteConn struct {
	net.Conn
	in, out func(typ byte, body []byte)
	mu      sync.Mutex
	rdone   bool
	wdone   bool
	pending []byte
	ready   []byte
	tmp     [16384]byte
}

func (c *rewriteConn) Write(b []byte) (int, error) {
	if c.out != nil && !c.wdone {
		b = append([]byte(nil), b...)
		c.wdone = !walkHandshake(b, c.out)
	}
	return c.Conn.Write(b)
}

func (c *rewriteConn) Read(b []byte) (int, error) {
	if c.in == nil {
		return c.Conn.Read(b)
	}
	for len(c.ready) == 0 {
		if c.rdone {
			c.ready, c.pending = c.pending, nil
			if len(c.ready) > 0 {
				break
			}
			return c.Conn.Read(b)
		}
		n, err := c.Conn.Read(c.tmp[:])
		c.pending = append(c.pending, c.tmp[:n]...)
		if k := recordLen(c.pending); k > 0 {
			rec := c.pending[:k]
			c.rdone = !walkHandshake(rec, c.in)
			c.ready = append(c.ready, rec...)
			c.pending = append([]byte(nil), c.pending[k:]...)
		}
		if err != nil && len(c.ready) == 0 {
			return 0, err
		}
	}
	n := copy(b, c.ready)
	c.ready = c.ready[n:]
	return n, nil
}

// fillSHA1 overwrites a signature scheme list with SHA-1 schemes only.
func fillSHA1(list []byte) {
	for i := 0; i+1 < len(list); i += 2 {
		s := uint16(sigECDSASHA1)
		if i/2%2 == 1 {
			s = sigPKCS1SHA1
		}
		list[i], list[i+1] = byte(s>>8), byte(s)
	}
}

// clientHelloExt returns the data of extension typ in a ClientHello body, and
// the offset of its type field in body.
func clientHelloExt(body []byte, typ uint16) ([]byte, int) {
	off := 2 + 32
	off += 1 + int(body[off])
	off += 2 + (int(body[off])<<8 | int(body[off+1]))
	off += 1 + int(body[off])
	end := off + 2 + (int(body[off])<<8 | int(body[off+1]))
	off += 2
	for off+4 <= end {
		t := uint16(body[off])<<8 | uint16(body[off+1])
		n := int(body[off+2])<<8 | int(body[off+3])
		if t == typ {
			return body[off+4 : off+4+n], off
		}
		off += 4 + n
	}
	return nil, -1
}

func sha1OnlyClientHello(typ byte, body []byte) {
	if typ == 1 {
		if ext, _ := clientHelloExt(body, 13); ext != nil {
			fillSHA1(ext[2:])
		}
	}
}

func noSigAlgsClientHello(typ byte, body []byte) {
	if typ == 1 {
		if _, off := clientHelloExt(body, 13); off >= 0 {
			body[off], body[off+1] = 0xfe, 0x0d // unknown extension
		}
	}
}

func sha1OnlyCertificateRequest(typ byte, body []byte) {
	if typ == 13 {
		off := 1 + int(body[0])
		n := int(body[off])<<8 | int(body[off+1])
		fillSHA1(body[off+2 : off+2+n])
	}
}

func dialStd(ln net.Listener, cfg *stdtls.Config, in, out func(byte, []byte)) error {
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return err
	}
	defer raw.Close()
	c := stdtls.Client(&rewriteConn{Conn: raw, in: in, out: out}, cfg)
	if err := c.Handshake(); err != nil {
		return err
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		return err
	}
	_, err = c.Read(make([]byte, 5))
	return err
}

// TestSHA1ServerKeyExchangeRejected: a TLS 1.2 client offering only SHA-1
// signature algorithms, or none at all, must be rejected by the llib server.
func TestSHA1ServerKeyExchangeRejected(t *testing.T) {
	p := newPKI(t)
	cases := []struct {
		name    string
		rewrite func(byte, []byte)
		want    string
	}{
		{"sha1only", sha1OnlyClientHello, "signature algorithms"},
		{"missing", noSigAlgsClientHello, "missing signature_algorithms"},
	}
	for _, m := range modes {
		for _, tc := range cases {
			t.Run(m.name+"/"+tc.name, func(t *testing.T) {
				ln := listen(t)
				ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}}, m.nonBlock)
				cerr := dialStd(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test", MaxVersion: stdtls.VersionTLS12}, nil, tc.rewrite)
				r := <-ch
				if cerr == nil || r.err == nil {
					t.Fatalf("handshake succeeded: client=%v server=%v", cerr, r.err)
				}
				if !strings.Contains(r.err.Error(), tc.want) {
					t.Fatalf("server error = %v, want %q", r.err, tc.want)
				}
			})
		}
	}
	// Sanity check: the unmodified stdlib client still connects over TLS 1.2.
	for _, m := range modes {
		ln := listen(t)
		ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}}, m.nonBlock)
		cerr := dialStd(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test", MaxVersion: stdtls.VersionTLS12}, nil, nil)
		if r := <-ch; cerr != nil || r.err != nil {
			t.Fatalf("%s: plain TLS 1.2 failed: client=%v server=%v", m.name, cerr, r.err)
		}
	}
}

// TestSHA1CertificateVerifyRejected: a TLS 1.2 client certificate signed with
// SHA-1 in CertificateVerify must be rejected by the llib server.
func TestSHA1CertificateVerifyRejected(t *testing.T) {
	p := newPKI(t)
	cliCert := stdtls.Certificate{Certificate: [][]byte{p.cliDER, p.interDER}, PrivateKey: p.cliKey}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			ln := listen(t)
			ch := serveLlib(t, ln, &ltls.Config{
				Certificates: []ltls.Certificate{p.lServerCert()},
				ClientAuth:   ltls.RequireAnyClientCert,
			}, m.nonBlock)
			cerr := dialStd(ln, &stdtls.Config{
				RootCAs: p.pool, ServerName: "example.test", MaxVersion: stdtls.VersionTLS12,
				Certificates: []stdtls.Certificate{cliCert},
			}, sha1OnlyCertificateRequest, nil)
			r := <-ch
			if cerr == nil || r.err == nil {
				t.Fatalf("handshake succeeded: client=%v server=%v", cerr, r.err)
			}
			if !strings.Contains(r.err.Error(), "client certificate used with invalid signature algorithm") {
				t.Fatalf("server error = %v", r.err)
			}
		})
	}
}

// TestSHA1ClientRejectsServerKeyExchange: an llib client must not accept a
// SHA-1 ServerKeyExchange signature, even from a server that thinks the client
// offered it.
func TestSHA1ClientRejectsServerKeyExchange(t *testing.T) {
	p := newPKI(t)
	ln := listen(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		s := stdtls.Server(c, &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()}, MaxVersion: stdtls.VersionTLS12})
		s.Handshake()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := ltls.Client(&rewriteConn{Conn: raw, out: sha1OnlyClientHello}, &ltls.Config{RootCAs: p.pool, ServerName: "example.test"})
	err = c.Handshake()
	if err == nil || !strings.Contains(err.Error(), "invalid signature algorithm") {
		t.Fatalf("client error = %v", err)
	}
}

// TestClientHelloNoSHA1: llib's ClientHello must not offer SHA-1 in
// signature_algorithms (but keeps it in signature_algorithms_cert).
func TestClientHelloNoSHA1(t *testing.T) {
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
	var sigAlgs, sigAlgsCert []byte
	walkHandshake(hello[:recordLen(hello)], func(typ byte, body []byte) {
		if typ == 1 {
			sigAlgs, _ = clientHelloExt(body, 13)
			sigAlgsCert, _ = clientHelloExt(body, 50)
		}
	})
	has := func(ext []byte, s uint16) bool {
		for i := 2; i+1 < len(ext); i += 2 {
			if uint16(ext[i])<<8|uint16(ext[i+1]) == s {
				return true
			}
		}
		return false
	}
	if len(sigAlgs) == 0 {
		t.Fatal("no signature_algorithms extension")
	}
	if !has(sigAlgs, 0x0403) {
		t.Errorf("signature_algorithms lost ECDSAWithP256AndSHA256: %x", sigAlgs)
	}
	for _, s := range []uint16{sigPKCS1SHA1, sigECDSASHA1} {
		if has(sigAlgs, s) {
			t.Errorf("signature_algorithms offers %04x: %x", s, sigAlgs)
		}
		if !has(sigAlgsCert, s) {
			t.Errorf("signature_algorithms_cert lacks %04x: %x", s, sigAlgsCert)
		}
	}
}
