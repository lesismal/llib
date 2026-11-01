//go:build go1.26
// +build go1.26

package interoptest

import (
	stdtls "crypto/tls"
	"testing"

	ltls "github.com/lesismal/llib/std/crypto/tls"
)

// TestHRRStdClient forces a HelloRetryRequest from the llib server: the stdlib
// client sends key shares for X25519 (and the hybrid) up front, while the
// server only accepts P-384 or P-521, so the second ClientHello carries the share.
func TestHRRStdClient(t *testing.T) {
	p := newPKI(t)
	for _, m := range modes {
		for _, srv := range [][]ltls.CurveID{{ltls.CurveP384}, {ltls.CurveP521}} {
			ln := listen(t)
			ch := serveLlib(t, ln, &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}, CurvePreferences: srv}, m.nonBlock)
			ccfg := &stdtls.Config{RootCAs: p.pool, ServerName: "example.test",
				CurvePreferences: []stdtls.CurveID{stdtls.X25519, stdtls.CurveID(srv[0])}}
			st, err := stdClient(ln, ccfg)
			r := <-ch
			if err != nil || r.err != nil {
				t.Fatalf("%s %v: client err=%v server err=%v", m.name, srv, err, r.err)
			}
			if st.CurveID != stdtls.CurveID(srv[0]) || !st.HelloRetryRequest {
				t.Fatalf("%s %v: curve %v hrr %v", m.name, srv, st.CurveID, st.HelloRetryRequest)
			}
		}
	}
}
