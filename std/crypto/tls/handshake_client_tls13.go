// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"hash"
	"sync/atomic"
	"time"
)

type clientHandshakeStateTLS13 struct {
	c           *Conn
	serverHello *serverHelloMsg
	hello       *clientHelloMsg
	ecdheParams ecdheParameters

	session     *ClientSessionState
	earlySecret []byte
	binderKey   []byte

	certReq       *certificateRequestMsgTLS13
	usingPSK      bool
	sentDummyCCS  bool
	suite         *cipherSuiteTLS13
	transcript    hash.Hash
	masterSecret  []byte
	trafficSecret []byte // client_application_traffic_secret_0

	echContext *echClientContext
}

// handshake requires hs.c, hs.hello, hs.serverHello, hs.ecdheParams, and,
// optionally, hs.session, hs.earlySecret and hs.binderKey to be set.
func (hs *clientHandshakeStateTLS13) handshake() error {
	c := hs.c

	// The server must not select TLS 1.3 in a renegotiation. See RFC 8446,
	// sections 4.1.2 and 4.1.3.
	if c.handshakes > 0 {
		c.sendAlert(alertProtocolVersion)
		return errors.New("tls: server selected TLS 1.3 in a renegotiation")
	}

	// Consistency check on the presence of a keyShare and its parameters.
	if hs.ecdheParams == nil || len(hs.hello.keyShares) == 0 || len(hs.hello.keyShares) > 2 {
		return c.sendAlert(alertInternalError)
	}

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	hs.transcript = hs.suite.hash.New()
	hs.transcript.Write(hs.hello.marshal())

	if hs.echContext != nil {
		hs.echContext.innerTranscript = hs.suite.hash.New()
		hs.echContext.innerTranscript.Write(hs.echContext.innerHello.marshal())
	}

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		if err := hs.sendDummyChangeCipherSpec(); err != nil {
			return err
		}
		if err := hs.processHelloRetryRequest(); err != nil {
			return err
		}
	}

	if hs.echContext != nil {
		// The server signals that it accepted ECH with the last 8 bytes of
		// its random. See RFC 9849, Section 7.2.
		serverHello := hs.serverHello.marshal()
		confTranscript := cloneHash(hs.echContext.innerTranscript, hs.suite.hash)
		confTranscript.Write(serverHello[:30])
		confTranscript.Write(make([]byte, 8))
		confTranscript.Write(serverHello[38:])
		prk := hs.suite.extract(hs.echContext.innerHello.random, nil)
		acceptConfirmation := hs.suite.expandLabel(prk, "ech accept confirmation", confTranscript.Sum(nil), 8)
		if subtle.ConstantTimeCompare(acceptConfirmation, hs.serverHello.random[len(hs.serverHello.random)-8:]) == 1 {
			hs.hello = hs.echContext.innerHello
			c.serverName = c.config.ServerName
			hs.transcript = hs.echContext.innerTranscript
			c.echAccepted = true

			if hs.serverHello.encryptedClientHello != nil {
				c.sendAlert(alertUnsupportedExtension)
				return errors.New("tls: unexpected encrypted client hello extension in server hello despite ECH being accepted")
			}
		} else {
			hs.echContext.echRejected = true
		}
	}

	hs.transcript.Write(hs.serverHello.marshal())

	c.buffering = true
	if err := hs.processServerHello(); err != nil {
		return err
	}
	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}
	if err := hs.establishHandshakeKeys(); err != nil {
		return err
	}
	if err := hs.readServerParameters(); err != nil {
		return err
	}
	if err := hs.readServerCertificate(); err != nil {
		return err
	}
	if err := hs.readServerFinished(); err != nil {
		return err
	}
	if err := hs.sendClientCertificate(); err != nil {
		return err
	}
	if err := hs.sendClientFinished(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}

	if hs.echContext != nil && hs.echContext.echRejected {
		c.sendAlert(alertECHRequired)
		return &ECHRejectionError{hs.echContext.retryConfigs}
	}

	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// checkServerHelloOrHRR does validity checks that apply to both ServerHello and
// HelloRetryRequest messages. It sets hs.suite.
func (hs *clientHandshakeStateTLS13) checkServerHelloOrHRR() error {
	c := hs.c

	if hs.serverHello.supportedVersion == 0 {
		c.sendAlert(alertMissingExtension)
		return errors.New("tls: server selected TLS 1.3 using the legacy version field")
	}

	if hs.serverHello.supportedVersion != VersionTLS13 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid version after a HelloRetryRequest")
	}

	if hs.serverHello.vers != VersionTLS12 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an incorrect legacy version")
	}

	if hs.serverHello.ocspStapling ||
		hs.serverHello.ticketSupported ||
		hs.serverHello.extendedMasterSecret ||
		hs.serverHello.secureRenegotiationSupported ||
		len(hs.serverHello.secureRenegotiation) != 0 ||
		len(hs.serverHello.alpnProtocol) != 0 ||
		len(hs.serverHello.scts) != 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a ServerHello extension forbidden in TLS 1.3")
	}

	if !bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not echo the legacy session ID")
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported compression format")
	}

	selectedSuite := mutualCipherSuiteTLS13(hs.hello.cipherSuites, hs.serverHello.cipherSuite)
	if hs.suite != nil && selectedSuite != hs.suite {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server changed cipher suite after a HelloRetryRequest")
	}
	if selectedSuite == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}
	hs.suite = selectedSuite
	c.cipherSuite = hs.suite.id

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *clientHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	_, err := hs.c.writeRecord(recordTypeChangeCipherSpec, []byte{1})
	return err
}

// processHelloRetryRequest handles the HRR in hs.serverHello, modifies and
// resends hs.hello, and reads the new ServerHello into hs.serverHello.
func (hs *clientHandshakeStateTLS13) processHelloRetryRequest() error {
	c := hs.c

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. (The idea is that the server might offload transcript
	// storage to the client in the cookie.) See RFC 8446, Section 4.4.1.
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)
	hs.transcript.Write(hs.serverHello.marshal())

	// With ECH, the HelloRetryRequest applies to the inner ClientHello if the
	// server confirms it accepted ECH. See RFC 9849, Section 6.1.5.
	var isInnerHello bool
	hello := hs.hello
	if hs.echContext != nil {
		chHash = hs.echContext.innerTranscript.Sum(nil)
		hs.echContext.innerTranscript.Reset()
		hs.echContext.innerTranscript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
		hs.echContext.innerTranscript.Write(chHash)

		if hs.serverHello.encryptedClientHello != nil {
			if len(hs.serverHello.encryptedClientHello) != 8 {
				c.sendAlert(alertDecodeError)
				return errors.New("tls: malformed encrypted client hello extension")
			}

			confTranscript := cloneHash(hs.echContext.innerTranscript, hs.suite.hash)
			hrrHello := append([]byte{}, hs.serverHello.marshal()...)
			hrrHello = bytes.Replace(hrrHello, hs.serverHello.encryptedClientHello, make([]byte, 8), 1)
			confTranscript.Write(hrrHello)
			prk := hs.suite.extract(hs.echContext.innerHello.random, nil)
			acceptConfirmation := hs.suite.expandLabel(prk, "hrr ech accept confirmation", confTranscript.Sum(nil), 8)
			if subtle.ConstantTimeCompare(acceptConfirmation, hs.serverHello.encryptedClientHello) == 1 {
				hello = hs.echContext.innerHello
				c.serverName = c.config.ServerName
				isInnerHello = true
				c.echAccepted = true
			}
		}

		hs.echContext.innerTranscript.Write(hs.serverHello.marshal())
	} else if hs.serverHello.encryptedClientHello != nil {
		// Unsolicited ECH extension should be rejected.
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: unexpected encrypted client hello extension in serverHello")
	}

	// The only HelloRetryRequest extensions we support are key_share and
	// cookie, and clients must abort the handshake if the HRR would not result
	// in any change in the ClientHello.
	if hs.serverHello.selectedGroup == 0 && hs.serverHello.cookie == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an unnecessary HelloRetryRequest message")
	}

	if hs.serverHello.cookie != nil {
		hello.cookie = hs.serverHello.cookie
	}

	if hs.serverHello.serverShare.group != 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received malformed key_share extension")
	}

	// If the server sent a key_share extension selecting a group, ensure it's
	// a group we advertised but did not send a key share for, and send a key
	// share for it this time.
	if curveID := hs.serverHello.selectedGroup; curveID != 0 {
		curveOK := false
		for _, id := range hello.supportedCurves {
			if id == curveID {
				curveOK = true
				break
			}
		}
		if !curveOK {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server selected unsupported group")
		}
		if hs.keyShareParams(curveID) != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server sent an unnecessary HelloRetryRequest key_share")
		}
		var params ecdheParameters
		if curveID == X25519MLKEM768 {
			hybrid, err := generateX25519MLKEM768Parameters(c.config.rand())
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			params = hybrid
		} else {
			if _, ok := curveForCurveID(curveID); curveID != X25519 && !ok {
				c.sendAlert(alertInternalError)
				return errors.New("tls: CurvePreferences includes unsupported curve")
			}
			var err error
			params, err = generateECDHEParameters(c.config.rand(), curveID)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
		}
		hs.ecdheParams = params
		// Do not send the fallback X25519 key share in the second ClientHello.
		hello.keyShares = []keyShare{{group: curveID, data: params.PublicKey()}}
	}

	hello.raw = nil
	// The cookie is chosen by the server, make sure the second ClientHello can
	// still be encoded instead of panicking. See CVE-2022-41724.
	if _, err := hello.marshalChecked(); err != nil {
		c.sendAlert(alertIllegalParameter)
		return err
	}
	hello.raw = nil
	if len(hello.pskIdentities) > 0 {
		pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
		if pskSuite == nil {
			return c.sendAlert(alertInternalError)
		}
		if pskSuite.hash == hs.suite.hash {
			// Update binders and obfuscated_ticket_age.
			ticketAge := uint32(c.config.time().Sub(hs.session.receivedAt) / time.Millisecond)
			hello.pskIdentities[0].obfuscatedTicketAge = ticketAge + hs.session.ageAdd

			transcript := hs.suite.hash.New()
			transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
			transcript.Write(chHash)
			transcript.Write(hs.serverHello.marshal())
			transcript.Write(hello.marshalWithoutBinders())
			pskBinders := [][]byte{hs.suite.finishedHash(hs.binderKey, transcript)}
			hello.updateBinders(pskBinders)
		} else {
			// Server selected a cipher suite incompatible with the PSK.
			hello.pskIdentities = nil
			hello.pskBinders = nil
		}
	}

	if isInnerHello {
		// Any extensions which have changed in hello, but are mirrored in the
		// outer hello and compressed, need to be copied to the outer hello, so
		// they can be properly decompressed by the server. The only extensions
		// which may have changed are key_share and cookie.
		hs.hello.keyShares = hello.keyShares
		hs.hello.cookie = hello.cookie
		hs.echContext.innerHello = hello
		hs.echContext.innerTranscript.Write(hello.marshal())

		if err := computeAndUpdateOuterECHExtension(hs.hello, hs.echContext.innerHello, hs.echContext, false); err != nil {
			return err
		}
	} else {
		hs.hello = hello
	}

	hs.transcript.Write(hs.hello.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}
	hs.serverHello = serverHello
	c.serverHello = serverHello

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	return nil
}

// keyShareParams returns the private parameters for the key share of the given
// group sent in the current ClientHello, or nil if no such key share was sent.
func (hs *clientHandshakeStateTLS13) keyShareParams(group CurveID) ecdheParameters {
	sent := false
	for _, ks := range hs.hello.keyShares {
		if ks.group == group {
			sent = true
			break
		}
	}
	if !sent {
		return nil
	}
	if hs.ecdheParams.CurveID() == group {
		return hs.ecdheParams
	}
	if hybrid, ok := hs.ecdheParams.(*x25519MLKEM768Parameters); ok && group == X25519 {
		return hybrid.x25519
	}
	return nil
}

func (hs *clientHandshakeStateTLS13) processServerHello() error {
	c := hs.c

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: server sent two HelloRetryRequest messages")
	}

	if len(hs.serverHello.cookie) != 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a cookie in a normal ServerHello")
	}

	if hs.serverHello.selectedGroup != 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: malformed key_share extension")
	}

	if hs.serverHello.serverShare.group == 0 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not send a key share")
	}
	if hs.keyShareParams(hs.serverHello.serverShare.group) == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported group")
	}

	if !hs.serverHello.selectedIdentityPresent {
		return nil
	}

	if int(hs.serverHello.selectedIdentity) >= len(hs.hello.pskIdentities) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK")
	}

	if len(hs.hello.pskIdentities) != 1 || hs.session == nil {
		return c.sendAlert(alertInternalError)
	}
	pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
	if pskSuite == nil {
		return c.sendAlert(alertInternalError)
	}
	if pskSuite.hash != hs.suite.hash {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK and cipher suite pair")
	}

	hs.usingPSK = true
	c.didResume = true
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	c.scts = hs.session.scts
	return nil
}

func (hs *clientHandshakeStateTLS13) establishHandshakeKeys() error {
	c := hs.c

	params := hs.keyShareParams(hs.serverHello.serverShare.group)
	if params == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported group")
	}
	sharedKey := params.SharedKey(hs.serverHello.serverShare.data)
	if sharedKey == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid server key share")
	}
	c.curveID = hs.serverHello.serverShare.group

	earlySecret := hs.earlySecret
	if !hs.usingPSK {
		earlySecret = hs.suite.extract(nil, nil)
	}
	handshakeSecret := hs.suite.extract(sharedKey,
		hs.suite.deriveSecret(earlySecret, "derived", nil))

	clientSecret := hs.suite.deriveSecret(handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, clientSecret)
	serverSecret := hs.suite.deriveSecret(handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)
	if err := c.setReadTrafficSecret(hs.suite, serverSecret); err != nil {
		return err
	}

	err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.hello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	hs.masterSecret = hs.suite.extract(nil,
		hs.suite.deriveSecret(handshakeSecret, "derived", nil))

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerParameters() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(encryptedExtensions, msg)
	}
	hs.transcript.Write(encryptedExtensions.marshal())

	if encryptedExtensions.alpnProtocol != "" {
		if len(hs.hello.alpnProtocols) == 0 {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server advertised unrequested ALPN extension")
		}
		if mutualProtocol([]string{encryptedExtensions.alpnProtocol}, hs.hello.alpnProtocols) == "" {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server selected unadvertised ALPN protocol")
		}
		c.clientProtocol = encryptedExtensions.alpnProtocol
	}

	if hs.echContext != nil {
		if hs.echContext.echRejected {
			hs.echContext.retryConfigs = encryptedExtensions.echRetryConfigs
		} else if encryptedExtensions.echRetryConfigs != nil {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server sent encrypted client hello retry configs after accepting encrypted client hello")
		}
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerCertificate() error {
	c := hs.c

	// Either a PSK or a certificate is always used, but not both.
	// See RFC 8446, Section 4.1.1.
	if hs.usingPSK {
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	certReq, ok := msg.(*certificateRequestMsgTLS13)
	if ok {
		hs.transcript.Write(certReq.marshal())

		hs.certReq = certReq

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	if len(certMsg.certificate.Certificate) == 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received empty certificates message")
	}
	hs.transcript.Write(certMsg.marshal())

	c.scts = certMsg.certificate.SignedCertificateTimestamps
	c.ocspResponse = certMsg.certificate.OCSPStaple

	if err := c.verifyServerCertificate(certMsg.certificate.Certificate); err != nil {
		return err
	}

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certVerify, msg)
	}

	// See RFC 8446, Section 4.4.3.
	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
		sigHash, signed, certVerify.signature); err != nil {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}

	hs.transcript.Write(certVerify.marshal())

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerFinished() error {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	expectedMAC := hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	if !hmac.Equal(expectedMAC, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid server finished hash")
	}

	hs.transcript.Write(finished.marshal())

	// Derive secrets that take context through the server Finished.

	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)
	serverSecret := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	if err := c.setReadTrafficSecret(hs.suite, serverSecret); err != nil {
		return err
	}

	err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientCertificate() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	if hs.echContext != nil && hs.echContext.echRejected {
		// Don't authenticate to the ECH provider with the certificate meant
		// for the actual server: the handshake fails after this anyway.
		certMsg := new(certificateMsgTLS13)
		hs.transcript.Write(certMsg.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
		return nil
	}

	cert, err := c.getClientCertificate(&CertificateRequestInfo{
		AcceptableCAs:    hs.certReq.certificateAuthorities,
		SignatureSchemes: hs.certReq.supportedSignatureAlgorithms,
		Version:          c.vers,
	})
	if err != nil {
		return err
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *cert
	certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0

	hs.transcript.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	// If we sent an empty certificate message, skip the CertificateVerify.
	if len(cert.Certificate) == 0 {
		return nil
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true

	certVerifyMsg.signatureAlgorithm, err = selectSignatureScheme(c.vers, cert, hs.certReq.supportedSignatureAlgorithms)
	if err != nil {
		// getClientCertificate returned a certificate incompatible with the
		// CertificateRequestInfo supported signature algorithms.
		c.sendAlert(alertHandshakeFailure)
		return err
	}

	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerifyMsg.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	hs.transcript.Write(certVerifyMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certVerifyMsg.marshal()); err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientFinished() error {
	c := hs.c

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}

	hs.transcript.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}

	c.out.setTrafficSecret(hs.suite, hs.trafficSecret)

	if !c.config.SessionTicketsDisabled && c.config.ClientSessionCache != nil {
		c.resumptionSecret = hs.suite.deriveSecret(hs.masterSecret,
			resumptionLabel, hs.transcript)
	}

	return nil
}

func (c *Conn) handleNewSessionTicket(msg *newSessionTicketMsgTLS13) error {
	if !c.isClient {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: received new session ticket from a client")
	}

	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return nil
	}

	// See RFC 8446, Section 4.6.1.
	if msg.lifetime == 0 {
		return nil
	}
	lifetime := time.Duration(msg.lifetime) * time.Second
	if lifetime > maxSessionTicketLifetime {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: received a session ticket with invalid lifetime")
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil || c.resumptionSecret == nil {
		return c.sendAlert(alertInternalError)
	}

	// Save the resumption_master_secret and nonce instead of deriving the PSK
	// to do the least amount of work on NewSessionTicket messages before we
	// know if the ticket will be used. Forward secrecy of resumed connections
	// is guaranteed by the requirement for pskModeDHE.
	session := &ClientSessionState{
		sessionTicket:      msg.label,
		vers:               c.vers,
		cipherSuite:        c.cipherSuite,
		masterSecret:       c.resumptionSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
		receivedAt:         c.config.time(),
		nonce:              msg.nonce,
		useBy:              c.config.time().Add(lifetime),
		ageAdd:             msg.ageAdd,
		ocspResponse:       c.ocspResponse,
		scts:               c.scts,
	}

	cacheKey := clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
	c.config.ClientSessionCache.Put(cacheKey, session)

	return nil
}
