//go:build go1.26
// +build go1.26

//go:debug tlsmlkem=1

// The llib module declares go 1.16, so the test binary would otherwise get the
// stdlib's go 1.16 GODEBUG defaults, which keep X25519MLKEM768 disabled.

package interoptest

import (
	stdtls "crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	ltls "github.com/lesismal/llib/std/crypto/tls"
)

type stdResult struct {
	err   error
	state stdtls.ConnectionState
	chi   *stdtls.ClientHelloInfo
}

// serveStd accepts one connection with the stdlib server and echoes 5 bytes.
func serveStd(ln net.Listener, cfg *stdtls.Config) <-chan stdResult {
	ch := make(chan stdResult, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- stdResult{err: err}
			return
		}
		defer c.Close()
		var chi *stdtls.ClientHelloInfo
		cfg = cfg.Clone()
		cfg.GetConfigForClient = func(h *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			chi = h
			return nil, nil
		}
		s := stdtls.Server(c, cfg)
		s.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 5)
		if _, err := io.ReadFull(s, buf); err != nil {
			ch <- stdResult{err: err, chi: chi}
			return
		}
		_, err = s.Write(buf)
		ch <- stdResult{err: err, state: s.ConnectionState(), chi: chi}
	}()
	return ch
}

// llibClient dials ln with the llib client and echoes a message.
func llibClient(ln net.Listener, cfg *ltls.Config) (ltls.ConnectionState, error) {
	c, err := ltls.Dial("tcp", ln.Addr().String(), cfg)
	if err != nil {
		return ltls.ConnectionState{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("hello")); err != nil {
		return ltls.ConnectionState{}, err
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		return ltls.ConnectionState{}, err
	}
	if string(buf) != "hello" {
		return ltls.ConnectionState{}, io.ErrUnexpectedEOF
	}
	return c.ConnectionState(), nil
}

func TestMLKEMConstant(t *testing.T) {
	if uint16(ltls.X25519MLKEM768) != uint16(stdtls.X25519MLKEM768) || ltls.X25519MLKEM768.String() != "X25519MLKEM768" {
		t.Fatalf("X25519MLKEM768 = %d (%v)", ltls.X25519MLKEM768, ltls.X25519MLKEM768)
	}
}

// Go stdlib client -> llib server.
func TestMLKEMStdClientLlibServer(t *testing.T) {
	p := newPKI(t)
	cases := []struct {
		name       string
		serverPref []ltls.CurveID
		clientPref []stdtls.CurveID
		maxVers    uint16
		want       stdtls.CurveID
	}{
		{"default", nil, nil, 0, stdtls.X25519MLKEM768},
		{"client-disables-mlkem", nil, []stdtls.CurveID{stdtls.X25519, stdtls.CurveP256}, 0, stdtls.X25519},
		{"server-disables-mlkem", []ltls.CurveID{ltls.X25519, ltls.CurveP256}, nil, 0, stdtls.X25519},
		{"server-mlkem-only", []ltls.CurveID{ltls.X25519MLKEM768}, nil, 0, stdtls.X25519MLKEM768},
		{"server-prefers-p256", []ltls.CurveID{ltls.CurveP256, ltls.X25519MLKEM768}, []stdtls.CurveID{stdtls.CurveP256, stdtls.X25519MLKEM768}, 0, stdtls.X25519MLKEM768},
		{"tls12-default", nil, nil, stdtls.VersionTLS12, stdtls.X25519},
	}
	for _, m := range modes {
		for _, tc := range cases {
			t.Run(m.name+"/"+tc.name, func(t *testing.T) {
				ln := listen(t)
				scfg := &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}, CurvePreferences: tc.serverPref}
				ch := serveLlib(t, ln, scfg, m.nonBlock)
				st, err := stdClient(ln, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test", CurvePreferences: tc.clientPref, MaxVersion: tc.maxVers})
				r := <-ch
				if err != nil || r.err != nil {
					t.Fatalf("client err=%v server err=%v", err, r.err)
				}
				if st.CurveID != tc.want {
					t.Fatalf("stdlib client negotiated %v, want %v", st.CurveID, tc.want)
				}
				wantL := ltls.CurveID(tc.want)
				if st.Version != stdtls.VersionTLS13 {
					wantL = 0 // llib only reports CurveID for TLS 1.3
				}
				if r.state.CurveID != wantL {
					t.Fatalf("llib server reports %v, want %v", r.state.CurveID, wantL)
				}
			})
		}
	}
}

// llib client -> Go stdlib server.
func TestMLKEMLlibClientStdServer(t *testing.T) {
	p := newPKI(t)
	cases := []struct {
		name       string
		clientPref []ltls.CurveID
		serverPref []stdtls.CurveID
		maxVers    uint16
		want       stdtls.CurveID
	}{
		{"default", nil, nil, 0, stdtls.X25519MLKEM768},
		{"client-disables-mlkem", []ltls.CurveID{ltls.X25519, ltls.CurveP256}, nil, 0, stdtls.X25519},
		// The server picks the fallback X25519 share sent alongside the hybrid.
		{"server-disables-mlkem", nil, []stdtls.CurveID{stdtls.X25519, stdtls.CurveP256}, 0, stdtls.X25519},
		// The client sends only an X25519 key share; the server sends a HRR
		// selecting X25519MLKEM768.
		{"hrr-to-mlkem", []ltls.CurveID{ltls.X25519, ltls.X25519MLKEM768}, []stdtls.CurveID{stdtls.X25519MLKEM768}, 0, stdtls.X25519MLKEM768},
		// The client sends hybrid+X25519 shares; the server HRRs to P-256.
		{"hrr-from-mlkem", nil, []stdtls.CurveID{stdtls.CurveP256}, 0, stdtls.CurveP256},
		{"mlkem-only", []ltls.CurveID{ltls.X25519MLKEM768}, nil, 0, stdtls.X25519MLKEM768},
		{"tls12-default", nil, nil, ltls.VersionTLS12, stdtls.X25519},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln := listen(t)
			ch := serveStd(ln, &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()}, CurvePreferences: tc.serverPref})
			cs, err := llibClient(ln, &ltls.Config{RootCAs: p.pool, ServerName: "example.test", CurvePreferences: tc.clientPref, MaxVersion: tc.maxVers})
			r := <-ch
			if err != nil || r.err != nil {
				t.Fatalf("client err=%v server err=%v", err, r.err)
			}
			if r.state.CurveID != tc.want {
				t.Fatalf("stdlib server negotiated %v, want %v", r.state.CurveID, tc.want)
			}
			if r.state.Version == stdtls.VersionTLS13 && cs.CurveID != ltls.CurveID(tc.want) {
				t.Fatalf("llib client reports %v, want %v", cs.CurveID, tc.want)
			}
			if tc.maxVers == ltls.VersionTLS12 {
				for _, c := range r.chi.SupportedCurves {
					if c == stdtls.X25519MLKEM768 {
						t.Fatalf("TLS 1.2-only ClientHello advertised X25519MLKEM768: %v", r.chi.SupportedCurves)
					}
				}
			}
		})
	}
}

// llib client -> llib server, including a HelloRetryRequest to the hybrid.
func TestMLKEMLlibToLlib(t *testing.T) {
	p := newPKI(t)
	cases := []struct {
		name                   string
		clientPref, serverPref []ltls.CurveID
		want                   ltls.CurveID
		hrr                    bool
	}{
		{"default", nil, nil, ltls.X25519MLKEM768, false},
		{"fallback-x25519", nil, []ltls.CurveID{ltls.X25519}, ltls.X25519, false},
		{"hrr-to-mlkem", []ltls.CurveID{ltls.CurveP256, ltls.X25519MLKEM768}, []ltls.CurveID{ltls.X25519MLKEM768}, ltls.X25519MLKEM768, true},
		{"hrr-from-mlkem", []ltls.CurveID{ltls.X25519MLKEM768, ltls.CurveP256}, []ltls.CurveID{ltls.CurveP256}, ltls.CurveP256, true},
	}
	for _, m := range modes {
		for _, tc := range cases {
			t.Run(m.name+"/"+tc.name, func(t *testing.T) {
				ln := listen(t)
				ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}, CurvePreferences: tc.serverPref}, m.nonBlock)
				cs, err := llibClient(ln, &ltls.Config{RootCAs: p.pool, ServerName: "example.test", CurvePreferences: tc.clientPref})
				r := <-ch
				if err != nil || r.err != nil {
					t.Fatalf("client err=%v server err=%v", err, r.err)
				}
				if cs.CurveID != tc.want || r.state.CurveID != tc.want {
					t.Fatalf("client %v server %v, want %v", cs.CurveID, r.state.CurveID, tc.want)
				}
			})
		}
	}
}

// A malformed hybrid key share must be rejected, not panic.
func TestMLKEMBadClientShare(t *testing.T) {
	p := newPKI(t)
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			ln := listen(t)
			ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}}, m.nonBlock)
			// Use a stdlib client but corrupt the hybrid key share in flight:
			// the ML-KEM encapsulation key's first coefficient is set to q.
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			tc := stdtls.Client(&corruptConn{Conn: c}, &stdtls.Config{RootCAs: p.pool, ServerName: "example.test"})
			tc.SetDeadline(time.Now().Add(5 * time.Second))
			if err := tc.Handshake(); err == nil {
				t.Fatal("handshake with corrupted key share succeeded")
			}
			r := <-ch
			if r.err == nil {
				t.Fatal("server accepted corrupted key share")
			}
			if _, ok := r.err.(panicErr); ok {
				t.Fatal(r.err)
			}
			t.Logf("server error: %v", r.err)
		})
	}
}

// corruptConn patches the first write (the ClientHello) so that the
// X25519MLKEM768 key share carries an unreduced ML-KEM coefficient.
type corruptConn struct {
	net.Conn
	done bool
}

func (c *corruptConn) Write(b []byte) (int, error) {
	if !c.done {
		c.done = true
		// key_share entry: group 0x11ec, length 0x04c0 (1216 bytes).
		for i := 0; i+4 < len(b); i++ {
			if b[i] == 0x11 && b[i+1] == 0xec && b[i+2] == 0x04 && b[i+3] == 0xc0 {
				nb := append([]byte(nil), b...)
				nb[i+4] = 0x01 // low 8 bits of 3329 (0xd01)
				nb[i+5] = 0x0d | nb[i+5]&0xf0
				return c.Conn.Write(nb)
			}
		}
	}
	return c.Conn.Write(b)
}
