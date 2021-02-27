package parser

import (
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	lbytes "github.com/lesismal/llib/bytes"
)

// Parser .
type Parser struct {
	state    int
	buffer   *lbytes.Buffer
	request  *http.Request
	appendfn func(buf []byte)

	// todo
	readLimit int

	crPos         int
	lfPos         int
	colPos        int
	chunked       bool
	contentLength int64
	trailer       http.Header
}

// Append .
func (p *Parser) Append(buf []byte) {
	p.appendfn(buf)
}

func (p *Parser) resetPos() {
	p.crPos = -1
	p.lfPos = -1
	p.colPos = -1
}

// ReadRequestLine .
func (p *Parser) ReadRequestLine(data []byte) (*http.Request, bool, error) {
	var c byte
	var offset = p.buffer.Len()
	for i := 0; i < len(data); i++ {
		c = data[i]
		switch c {
		case CR:
			if p.crPos > 0 || offset+i < 16 {
				return nil, false, ErrInvalidData
			}
			if p.crPos < 0 {
				p.crPos = offset + i
			}
		case LF:
			if p.crPos != offset+i-1 {
				return nil, false, ErrInvalidData
			}
			if p.lfPos < 0 {
				p.lfPos = offset + i
			}

			var b []byte
			if offset == 0 {
				b = data[:i]
			} else {
				p.Append(data[0:i])
				b, _ = p.buffer.ReadAll()
				b = b[:len(b)-1]
			}
			method, requestURI, proto, ok := parseRequestLine(b)

			if !ok {
				return nil, false, badStringError("malformed HTTP request", string(data))
			}

			if !validMethod(method) {
				return nil, false, badStringError("invalid method", method)
			}

			protoMajor, protoMinor, ok := http.ParseHTTPVersion(proto)
			if !ok {
				return nil, false, badStringError("malformed HTTP version", proto)
			}

			rawurl := requestURI
			justAuthority := method == "CONNECT" && !strings.HasPrefix(rawurl, "/")
			if justAuthority {
				rawurl = "http://" + rawurl
			}

			u, err := url.ParseRequestURI(rawurl)
			if err != nil {
				return nil, false, err
			}

			if justAuthority {
				u.Scheme = ""
			}

			if p.request == nil {
				p.request = &http.Request{
					URL:    u,
					Header: http.Header{},
				}
			}

			p.request.Method = method
			p.request.Proto = proto
			p.request.ProtoMajor = protoMajor
			p.request.ProtoMinor = protoMinor

			p.state = StateHeader
			p.resetPos()

			return p.ReadHeader(data[i+1:])
		case COL:
			// if p.colPos < 0 {
			// 	p.colPos = i
			// }
			fmt.Println("+++ ReadRequestLine char:", c)
		default:
		}
	}
	p.Append(data)
	return nil, false, nil
}

// ReadHeader .
func (p *Parser) ReadHeader(data []byte) (*http.Request, bool, error) {
	var c byte
	var offset = p.buffer.Len()
	for i := 0; i < len(data); i++ {
		c = data[i]
		switch c {
		case CR:
			if p.crPos > 0 {
				return nil, false, ErrInvalidData
			}
			if p.crPos < 0 {
				p.crPos = offset + i
			}
		case LF:
			if p.crPos < 0 || p.crPos != offset+i-1 {
				return nil, false, ErrInvalidData
			}

			if p.crPos == 0 {
				p.state = StateBody
				p.resetPos()

				p.request.Host = p.request.URL.Host
				if p.request.Host == "" {
					p.request.Host = p.request.Header.Get("Host")
				}
				if deleteHostHeader {
					delete(p.request.Header, "Host")
				}

				fixPragmaCacheControl(p.request.Header)

				p.request.Close = shouldClose(p.request.ProtoMajor, p.request.ProtoMinor, p.request.Header, false)

				// todo
				// err = readTransfer(req, b)
				// if err != nil {
				// 	return nil, err
				// }
				chunked, err := parseTransferEncoding(p.request)
				if err != nil {
					return nil, false, err
				}
				p.chunked = chunked

				if p.request.Method == "HEAD" {
					p.request.ContentLength, err = parseContentLength(p.request.Header.Get("Content-Length"))
					if err != nil {
						return nil, false, err
					}
				} else {
					p.request.ContentLength, err = fixLength(false, 200, p.request.Method, p.request.Header, chunked)
					if err != nil {
						return nil, false, err
					}
				}

				// Trailer
				p.trailer, err = fixTrailer(p.request.Header, p.chunked)
				if err != nil {
					return nil, false, err
				}

				// Prepare body reader. ContentLength < 0 means chunked encoding
				// or close connection when finished, since multipart is not supported yet
				// switch {
				// case t.Chunked:
				// 	if noResponseBodyExpected(t.RequestMethod) || !bodyAllowedForStatus(t.StatusCode) {
				// 		t.Body = NoBody
				// 	} else {
				// 		t.Body = &body{src: internal.NewChunkedReader(r), hdr: msg, r: r, closing: t.Close}
				// 	}
				// case realLength == 0:
				// 	t.Body = NoBody
				// case realLength > 0:
				// 	t.Body = &body{src: io.LimitReader(r, realLength), closing: t.Close}
				// default:
				// 	// realLength < 0, i.e. "Content-Length" not mentioned in header
				// 	if t.Close {
				// 		// Close semantics (i.e. HTTP/1.0)
				// 		t.Body = &body{src: r, closing: t.Close}
				// 	} else {
				// 		// Persistent connection (i.e. HTTP/1.1)
				// 		t.Body = NoBody
				// 	}
				// }

				// // Unify output
				// switch rr := msg.(type) {
				// case *Request:
				// 	rr.Body = t.Body
				// 	rr.ContentLength = t.ContentLength
				// 	if t.Chunked {
				// 		rr.TransferEncoding = []string{"chunked"}
				// 	}
				// 	rr.Close = t.Close
				// 	rr.Trailer = t.Trailer
				// case *Response:
				// 	rr.Body = t.Body
				// 	rr.ContentLength = t.ContentLength
				// 	if t.Chunked {
				// 		rr.TransferEncoding = []string{"chunked"}
				// 	}
				// 	rr.Close = t.Close
				// 	rr.Trailer = t.Trailer
				// }

				// todo
				if isH2Upgrade(p.request) {
					// Because it's neither chunked, nor declared:
					p.request.ContentLength = -1

					// We want to give handlers a chance to hijack the
					// connection, but we need to prevent the Server from
					// dealing with the connection further if it's not
					// hijacked. Set Close to ensure that:
					p.request.Close = true
				}

				// todo
				// if err != nil {
				// 	if c.r.hitReadLimit() {
				// 		return nil, errTooLarge
				// 	}
				// 	return nil, err
				// }

				// if !http1ServerSupportsRequest(req) {
				// 	return nil, statusError{StatusHTTPVersionNotSupported, "unsupported protocol version"}
				// }

				// c.lastMethod = req.Method
				// c.r.setInfiniteReadLimit()

				// hosts, haveHost := req.Header["Host"]
				// isH2Upgrade := req.isH2Upgrade()
				// if req.ProtoAtLeast(1, 1) && (!haveHost || len(hosts) == 0) && !isH2Upgrade && req.Method != "CONNECT" {
				// 	return nil, badRequestError("missing required Host header")
				// }
				// if len(hosts) > 1 {
				// 	return nil, badRequestError("too many Host headers")
				// }
				// if len(hosts) == 1 && !httpguts.ValidHostHeader(hosts[0]) {
				// 	return nil, badRequestError("malformed Host header")
				// }
				// for k, vv := range req.Header {
				// 	if !httpguts.ValidHeaderFieldName(k) {
				// 		return nil, badRequestError("invalid header name")
				// 	}
				// 	for _, v := range vv {
				// 		if !httpguts.ValidHeaderFieldValue(v) {
				// 			return nil, badRequestError("invalid header value")
				// 		}
				// 	}
				// }
				// delete(req.Header, "Host")

				// ctx, cancelCtx := context.WithCancel(ctx)
				// req.ctx = ctx
				// req.RemoteAddr = c.remoteAddr
				// req.TLS = c.tlsState
				// if body, ok := req.Body.(*body); ok {
				// 	body.doEarlyClose = true
				// }

				// // Adjust the read deadline if necessary.
				// if !hdrDeadline.Equal(wholeReqDeadline) {
				// 	c.rwc.SetReadDeadline(wholeReqDeadline)
				// }

				// w = &response{
				// 	conn:          c,
				// 	cancelCtx:     cancelCtx,
				// 	req:           req,
				// 	reqBody:       req.Body,
				// 	handlerHeader: make(Header),
				// 	contentLength: -1,
				// 	closeNotifyCh: make(chan bool, 1),

				// 	// We populate these ahead of time so we're not
				// 	// reading from req.Header after their Handler starts
				// 	// and maybe mutates it (Issue 14940)
				// 	wants10KeepAlive: req.wantsHttp10KeepAlive(),
				// 	wantsClose:       req.wantsClose(),
				// }
				// if isH2Upgrade {
				// 	w.closeAfterReply = true
				// }
				// w.cw.res = w
				// w.w = newBufioWriterSize(&w.cw, bufferBeforeChunkingSize)

				return p.ReadBody(data[i+1:])
			}

			if p.colPos < 0 {
				b, _ := p.buffer.ReadAll()
				return nil, false, textproto.ProtocolError("malformed MIME header line: " + string(b))
			}

			if p.lfPos > 0 {
				p.lfPos = offset + i
			}
			p.lfPos = offset + i
			if p.lfPos < 16 {
				return nil, false, ErrInvalidData
			}

			var b []byte
			if offset == 0 {
				b = data[:i]
			} else {
				p.Append(data[0:i])
				b, _ = p.buffer.ReadAll()
				b = b[:len(b)-1]
			}

			// The first line cannot start with a leading space.
			if len(p.request.Header) == 0 && (b[0] == ' ' || b[0] == '\t') {
				return nil, false, textproto.ProtocolError("malformed MIME header initial line head: " + string(b))
			}

			key := string(trim(b[:p.colPos]))
			value := string(trim(b[p.colPos+1 : p.crPos]))
			p.request.Header.Add(key, value)

			p.resetPos()

			return p.ReadHeader(data[i+1:])
		case COL:
			if !(p.crPos < 0) {
				return nil, false, ErrInvalidData
			}
			if p.colPos < 0 {
				p.colPos = offset + i
			}
		default:
		}
	}
	p.Append(data)
	return nil, false, nil
}

// ReadBody .
func (p *Parser) ReadBody(data []byte) (*http.Request, bool, error) {
	p.resetPos()
	p.buffer.Reset()
	p.state = StateURL

	request := p.request
	p.request = nil
	return request, true, nil
}

// ReadRequest .
func (p *Parser) ReadRequest(data []byte) (*http.Request, bool, error) {
	switch p.state {
	case StateURL:
		return p.ReadRequestLine(data)
	case StateHeader:
		return p.ReadHeader(data)
	case StateBody:
		return p.ReadBody(data)
	default:
		fmt.Println("--- ReadRequest:", string(data))
	}
	return nil, false, nil
}

// New .
func New() *Parser {
	bb := lbytes.NewBuffer()
	return &Parser{
		buffer:   bb,
		appendfn: bb.Push,
		crPos:    -1,
		lfPos:    -1,
		colPos:   -1,
	}
}
