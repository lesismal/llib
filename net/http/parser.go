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

	crPos  int
	lfPos  int
	colPos int
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
	request := p.request
	p.request = nil
	p.state = StateURL
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
