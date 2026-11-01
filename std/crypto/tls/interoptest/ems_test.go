//go:build go1.26
// +build go1.26

package interoptest

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	ltls "github.com/lesismal/llib/std/crypto/tls"
)

// Extended Master Secret (RFC 7627) interop tests.
//
// The stdlib (Go 1.22+) refuses ExportKeyingMaterial on TLS <= 1.2 unless EMS
// was negotiated, so a successful stdlib EKM proves EMS was used, and equal
// EKM values on both peers prove both derived the same (extended) master
// secret.

var emsVersions = []struct {
	name   string
	v      uint16
	suites []uint16
}{
	{"TLS10", stdtls.VersionTLS10, []uint16{stdtls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}},
	{"TLS11", stdtls.VersionTLS11, []uint16{stdtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}},
	{"TLS12-SHA256", stdtls.VersionTLS12, []uint16{stdtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}},
	{"TLS12-SHA384", stdtls.VersionTLS12, []uint16{stdtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}},
}

const ekmLabel = "EXPERIMENTAL llib ems"

func ekmPair(t *testing.T, a, b func(string, []byte, int) ([]byte, error)) {
	t.Helper()
	ka, err := a(ekmLabel, []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("stdlib EKM failed (EMS not negotiated?): %v", err)
	}
	kb, err := b(ekmLabel, []byte("ctx"), 32)
	if err != nil {
		t.Fatalf("llib EKM failed: %v", err)
	}
	if !bytes.Equal(ka, kb) {
		t.Fatalf("EKM mismatch:\nstdlib %x\nllib   %x", ka, kb)
	}
}

// Stdlib client -> llib server, blocking and non-blocking, with and without a
// client certificate (CertificateVerify follows the EMS session hash).
func TestEMSStdClientLlibServer(t *testing.T) {
	p := newPKI(t)
	for _, m := range modes {
		for _, v := range emsVersions {
			for _, clientCert := range []bool{false, true} {
				name := fmt.Sprintf("%s/%s/clientCert=%v", m.name, v.name, clientCert)
				t.Run(name, func(t *testing.T) {
					ln := listen(t)
					scfg := &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}, MinVersion: ltls.VersionTLS10}
					ccfg := &stdtls.Config{RootCAs: p.pool, ServerName: "example.test",
						MinVersion: v.v, MaxVersion: v.v, CipherSuites: v.suites}
					if clientCert {
						scfg.ClientAuth = ltls.RequireAndVerifyClientCert
						scfg.ClientCAs = p.pool
						ccfg.Certificates = []stdtls.Certificate{{Certificate: [][]byte{p.cliDER, p.interDER}, PrivateKey: p.cliKey}}
					}
					ch := serveLlib(t, ln, scfg, m.nonBlock)
					st, err := stdClient(ln, ccfg)
					r := <-ch
					if err != nil || r.err != nil {
						t.Fatalf("client err=%v server err=%v", err, r.err)
					}
					if st.Version != v.v || st.CipherSuite != v.suites[0] {
						t.Fatalf("negotiated %x/%x", st.Version, st.CipherSuite)
					}
					ekmPair(t, st.ExportKeyingMaterial, r.state.ExportKeyingMaterial)
					if !bytes.Equal(st.TLSUnique, r.state.TLSUnique) || len(st.TLSUnique) == 0 {
						t.Fatalf("tls-unique mismatch: %x vs %x", st.TLSUnique, r.state.TLSUnique)
					}
				})
			}
		}
	}
}

// llib client -> stdlib server, full handshake then resumption.
func TestEMSLlibClientStdServer(t *testing.T) {
	p := newPKI(t)
	for _, v := range emsVersions {
		for _, clientCert := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/clientCert=%v", v.name, clientCert), func(t *testing.T) {
				scfg := &stdtls.Config{Certificates: []stdtls.Certificate{p.sServerCert()},
					MinVersion: stdtls.VersionTLS10}
				ccfg := &ltls.Config{RootCAs: p.pool, ServerName: "example.test",
					MinVersion: v.v, MaxVersion: v.v, CipherSuites: v.suites,
					ClientSessionCache: ltls.NewLRUClientSessionCache(4)}
				if clientCert {
					scfg.ClientAuth = stdtls.RequireAndVerifyClientCert
					scfg.ClientCAs = p.pool
					ccfg.Certificates = []ltls.Certificate{{Certificate: [][]byte{p.cliDER, p.interDER}, PrivateKey: p.cliKey}}
				}
				for i := 0; i < 2; i++ {
					ln := listen(t)
					sch := make(chan stdtls.ConnectionState, 1)
					go func() {
						defer close(sch)
						c, err := ln.Accept()
						if err != nil {
							return
						}
						s := stdtls.Server(c, scfg)
						defer s.Close()
						s.SetDeadline(time.Now().Add(5 * time.Second))
						buf := make([]byte, 5)
						if _, err := io.ReadFull(s, buf); err != nil {
							t.Errorf("stdlib server: %v", err)
							return
						}
						s.Write(buf)
						sch <- s.ConnectionState()
					}()
					c, err := ltls.Dial("tcp", ln.Addr().String(), ccfg)
					if err != nil {
						t.Fatalf("conn %d: dial: %v", i, err)
					}
					c.Write([]byte("hello"))
					buf := make([]byte, 5)
					if _, err := io.ReadFull(c, buf); err != nil {
						t.Fatalf("conn %d: read: %v", i, err)
					}
					cs := c.ConnectionState()
					c.Close()
					ss, ok := <-sch
					if !ok {
						t.Fatalf("conn %d: server failed", i)
					}
					if cs.DidResume != (i == 1) || ss.DidResume != (i == 1) {
						t.Fatalf("conn %d: resume client=%v server=%v", i, cs.DidResume, ss.DidResume)
					}
					ekmPair(t, ss.ExportKeyingMaterial, cs.ExportKeyingMaterial)
				}
			})
		}
	}
}

// Stdlib client resumes a ticket from the llib server; the EMS flag must
// survive in the ticket, or the stdlib client would reject the resumption.
func TestEMSResumptionLlibServer(t *testing.T) {
	p := newPKI(t)
	for _, m := range modes {
		for _, v := range emsVersions {
			t.Run(m.name+"/"+v.name, func(t *testing.T) {
				scfg := &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}, MinVersion: ltls.VersionTLS10}
				ccfg := &stdtls.Config{RootCAs: p.pool, ServerName: "example.test",
					MinVersion: v.v, MaxVersion: v.v, CipherSuites: v.suites,
					ClientSessionCache: stdtls.NewLRUClientSessionCache(4)}
				for i := 0; i < 2; i++ {
					ln := listen(t)
					ch := serveLlib(t, ln, scfg, m.nonBlock)
					st, err := stdClient(ln, ccfg)
					r := <-ch
					if err != nil || r.err != nil {
						t.Fatalf("conn %d: client err=%v server err=%v", i, err, r.err)
					}
					if st.DidResume != (i == 1) || r.state.DidResume != (i == 1) {
						t.Fatalf("conn %d: resume client=%v server=%v", i, st.DidResume, r.state.DidResume)
					}
					ekmPair(t, st.ExportKeyingMaterial, r.state.ExportKeyingMaterial)
					if len(r.state.TLSUnique) == 0 {
						t.Fatalf("conn %d: no tls-unique with EMS", i)
					}
				}
			})
		}
	}
}

// ---------- OpenSSL as a client that can disable EMS ----------

type sslResult struct {
	reused bool
	ems    string // "yes" / "no"
	ekm    []byte
	out    string
}

var (
	reEMS = regexp.MustCompile(`Extended master secret: (\w+)`)
	reEKM = regexp.MustCompile(`Keying material: ([0-9A-Fa-f]+)`)
)

func opensslClient(t *testing.T, addr string, caFile string, args ...string) sslResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	base := []string{"s_client", "-connect", addr, "-servername", "example.test",
		"-CAfile", caFile, "-tls1_2", "-ign_eof",
		"-keymatexport", ekmLabel, "-keymatexportlen", "32"}
	cmd := exec.CommandContext(ctx, "openssl", append(base, args...)...)
	cmd.Stdin = strings.NewReader("hello")
	out, _ := cmd.CombinedOutput()
	s := string(out)
	res := sslResult{out: s}
	res.reused = strings.Contains(s, "Reused, TLSv1.2")
	if m := reEMS.FindStringSubmatch(s); m != nil {
		res.ems = m[1]
	}
	if m := reEKM.FindStringSubmatch(s); m != nil {
		fmt.Sscanf(m[1], "%x", &res.ekm)
	}
	return res
}

func TestEMSOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	if out, _ := exec.Command("openssl", "s_client", "-help").CombinedOutput(); !strings.Contains(string(out), "-no_ems") {
		t.Skip("openssl without -no_ems")
	}
	p := newPKI(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.caDER}), 0600)
	noEMS := filepath.Join(dir, "noems.sess")
	withEMS := filepath.Join(dir, "ems.sess")

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			scfg := &ltls.Config{Certificates: []ltls.Certificate{p.lServerCert()}}
			run := func(wantServerErr bool, args ...string) (sslResult, result) {
				t.Helper()
				ln := listen(t)
				ch := serveLlib(t, ln, scfg, m.nonBlock)
				res := opensslClient(t, ln.Addr().String(), caFile, args...)
				ln.Close()
				var r result
				select {
				case r = <-ch:
				case <-time.After(10 * time.Second):
					t.Fatalf("server did not finish")
				}
				if (r.err != nil) != wantServerErr {
					t.Fatalf("server err=%v (want error: %v)\nopenssl output:\n%s", r.err, wantServerErr, res.out)
				}
				return res, r
			}
			checkEKM := func(res sslResult, r result) {
				t.Helper()
				k, err := r.state.ExportKeyingMaterial(ekmLabel, nil, 32)
				if err != nil || !bytes.Equal(k, res.ekm) {
					t.Fatalf("EKM mismatch: llib %x (%v) openssl %x", k, err, res.ekm)
				}
			}

			// 1. Full handshake with EMS, and without EMS.
			res, r := run(false, "-sess_out", withEMS)
			if res.ems != "yes" || res.reused {
				t.Fatalf("EMS full handshake: ems=%q reused=%v", res.ems, res.reused)
			}
			checkEKM(res, r)
			res, r = run(false, "-no_ems", "-sess_out", noEMS)
			if res.ems != "no" || res.reused {
				t.Fatalf("non-EMS full handshake: ems=%q reused=%v", res.ems, res.reused)
			}
			checkEKM(res, r)

			// 2. Plain resumptions keep working in both cases.
			res, r = run(false, "-sess_in", withEMS)
			if !res.reused || res.ems != "yes" || !r.state.DidResume {
				t.Fatalf("EMS resumption: reused=%v ems=%q", res.reused, res.ems)
			}
			checkEKM(res, r)
			res, r = run(false, "-no_ems", "-sess_in", noEMS)
			if !res.reused || res.ems != "no" || !r.state.DidResume {
				t.Fatalf("non-EMS resumption: reused=%v ems=%q", res.reused, res.ems)
			}
			checkEKM(res, r)

			// 3. RFC 7627 5.3: a non-EMS session offered in an EMS ClientHello
			// must not be resumed; a full EMS handshake happens instead.
			res, r = run(false, "-sess_in", noEMS)
			if res.reused || res.ems != "yes" || r.state.DidResume {
				t.Fatalf("non-EMS session resumed into EMS: reused=%v ems=%q", res.reused, res.ems)
			}
			checkEKM(res, r)

			// 4. RFC 7627 5.3: an EMS session offered without EMS must abort.
			res, r = run(true, "-no_ems", "-sess_in", withEMS)
			if res.reused {
				t.Fatalf("EMS session resumed without EMS")
			}
			if !strings.Contains(r.err.Error(), "extended_master_secret") {
				t.Fatalf("unexpected server error: %v", r.err)
			}
		})
	}
}
