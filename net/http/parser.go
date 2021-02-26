package parser

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// StateURL .
	StateURL = 0

	// StateHeader .
	StateHeader = 1

	// StateBody .
	StateBody = 2
)

const (
	// LineTypeURL .
	LineTypeURL = 1
	// LineTypeHeader .
	LineTypeHeader = 2
	// LineTypeBody .
	LineTypeBody = 3
)

// Parser .
type Parser struct {
	state    int
	buffer   *HTTPBuffer
	request  *http.Request
	response *http.Response
	appendfn func(buf []byte)
}

// Append .
func (p *Parser) Append(buf []byte) {
	p.appendfn(buf)
}

// ReadRequest .
func (p *Parser) ReadRequest() (*http.Request, bool, error) {
	for {
		switch p.state {
		case StateURL:
			method, requestURI, proto, err := p.buffer.ReadRequestLine()
			if err == ErrDataNotEnouth {
				return nil, false, nil
			}
			if err != nil {
				return nil, false, err
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
		case StateHeader:
			for {
				key, value, ok, err := p.buffer.ReadHeader()
				if err == ErrDataNotEnouth {
					return nil, false, nil
				}
				if err != nil {
					return nil, false, err
				}
				if ok {
					p.request.Header.Add(key, value)
				} else {
					p.state = StateBody
					break
				}
			}
		case StateBody:
			p.state = StateURL
			return p.request, true, nil
		}
	}
}

// ReadResponse .
func (p *Parser) ReadResponse() (*http.Response, bool, error) {
	for {
		switch p.state {
		case StateURL:
			method, requestURI, proto, status, err := p.buffer.ReadResponseLine()
			if err == ErrDataNotEnouth {
				return nil, false, nil
			}
			if err != nil {
				return nil, false, err
			}
			request := &http.Request{}
			response := &http.Response{
				Request: request,
			}

			response.StatusCode, err = strconv.Atoi(status)
			if err != nil {
				return nil, false, err
			}
			url, err := url.Parse(requestURI)
			if err != nil {
				return nil, false, err
			}

			request.URL = url
			request.Method = method
			request.Proto = proto
			response.Proto = proto
			response.Status = status

			p.state = StateHeader
		case StateHeader:
			for {
				key, value, ok, err := p.buffer.ReadHeader()
				if err == ErrDataNotEnouth {
					return nil, false, nil
				}
				if err != nil {
					return nil, false, err
				}
				if ok {
					p.response.Request.Header.Add(key, value)
				} else {
					p.state = StateBody
					break
				}
			}
		case StateBody:
			p.state = StateURL
			return p.response, true, nil
		}
	}
}

// New .
func New() *Parser {
	hb := NewHTTPBuffer()
	return &Parser{
		buffer:   hb,
		appendfn: hb.Push,
	}
}
