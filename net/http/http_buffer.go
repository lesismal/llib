package parser

import (
	"bytes"
	"errors"
	"fmt"
	"net/textproto"
	"strings"

	"github.com/golang/net/http/httpguts"
	lbytes "github.com/lesismal/llib/bytes"
)

var (
	// ErrDataNotEnouth .
	ErrDataNotEnouth = errors.New("data not enougth")
	// ErrInvalidData .
	ErrInvalidData = errors.New("invalid data")
)

const (
	// CR .
	CR = '\r'
	// LF .
	LF = '\n'
	// COL .
	COL = ':'
	// SPA .
	SPA = ' '
)

// HTTPBuffer .
type HTTPBuffer struct {
	lbytes.Buffer
	crPos    []int
	lfPos    []int
	colPos   []int
	offset   int
	colExist bool
}

// Push .
func (hb *HTTPBuffer) Push(b []byte) {
	var c byte
	var l = hb.Len()
	for i := 0; i < len(b); i++ {
		c = b[i]
		switch c {
		case CR:
			hb.crPos = append(hb.crPos, hb.offset+l+i)
		case LF:
			hb.lfPos = append(hb.lfPos, hb.offset+l+i)
			hb.colExist = false
		case COL:
			if !hb.colExist {
				hb.colExist = true
				hb.colPos = append(hb.colPos, hb.offset+l+i)
			}
		default:
		}
	}
	hb.Buffer.Push(b)
}

// ReadRequestLine .
func (hb *HTTPBuffer) ReadRequestLine() (method string, requestURI string, proto string, err error) {
	if len(hb.crPos) < 1 || len(hb.lfPos) < 1 {
		err = ErrDataNotEnouth
		return
	}
	if hb.crPos[0]+1 != hb.lfPos[0] {
		err = ErrInvalidData
		return
	}

	l := hb.lfPos[0] - hb.offset + 1
	data, _ := hb.Pop(l)
	if len(data) < 16 {
		err = ErrInvalidData
		return
	}
	data = data[:len(data)-2]
	hb.offset += l

	hb.crPos = hb.crPos[1:]
	hb.lfPos = hb.lfPos[1:]

	method, requestURI, proto, ok := parseRequestLine(data)
	if !ok {
		err = badStringError("malformed HTTP request", string(data))
		return
	}

	if !validMethod(method) {
		err = badStringError("invalid method", method)
		return
	}

	return
}

// ReadResponseLine .
func (hb *HTTPBuffer) ReadResponseLine() (method string, requestURI string, proto string, status string, err error) {
	if len(hb.crPos) < 1 || len(hb.lfPos) < 1 {
		err = ErrDataNotEnouth
		return
	}
	if hb.crPos[0]+1 != hb.lfPos[0] {
		err = ErrInvalidData
		return
	}

	l := hb.lfPos[0] + 1 - hb.offset
	data, _ := hb.Pop(l)

	hb.offset += l

	hb.crPos = hb.crPos[1:]
	hb.lfPos = hb.lfPos[1:]

	strArr := strings.Split(string(data), " ")
	switch len(strArr) {
	case 4:
		method, requestURI, proto, status = strArr[0], strArr[1], strArr[2], strArr[3]
	default:
		err = ErrInvalidData
	}
	return
}

// ReadHeader .
func (hb *HTTPBuffer) ReadHeader(isFirstLine bool) (headKey string, headValue string, ok bool, err error) {
	if len(hb.crPos) < 1 || len(hb.lfPos) < 1 {
		err = ErrDataNotEnouth
		return
	}
	if hb.crPos[0]+1 != hb.lfPos[0] {
		err = ErrInvalidData
		return
	}
	if hb.crPos[0]-hb.offset == 0 {
		hb.Pop(2)
		hb.offset += 2
		ok = false
		return
	}

	if len(hb.colPos) == 0 {
		err = ErrInvalidData
		return
	}

	var bKey, bValue []byte
	l := hb.colPos[0] - hb.offset + 1
	bKey, err = hb.Pop(l)
	// The first line cannot start with a leading space.
	if bKey[0] == ' ' || bKey[0] == '\t' {
		err = textproto.ProtocolError("malformed MIME header initial line head key: " + string(bKey))
		return
	}

	bKey = bKey[:l-1]
	hb.offset += l
	l = hb.crPos[0] - hb.colPos[0] + 1
	bValue, err = hb.Pop(l)
	bValue = bValue[:l-2]
	hb.offset += l

	for i := 0; i < len(bKey); i++ {
		if bKey[i] != ' ' {
			bKey = bKey[i:]
			break
		}
	}
	for i := len(bKey) - 1; i >= 0; i-- {
		if bKey[i] != ' ' {
			bKey = bKey[:i+1]
			break
		}
	}
	for i := 0; i < len(bValue); i++ {
		if bValue[i] != ' ' {
			bValue = bValue[i:]
			break
		}
	}
	for i := len(bValue) - 1; i >= 0; i-- {
		if bValue[i] != ' ' {
			bValue = bValue[:i+1]
			break
		}
	}
	headKey = string(bKey)
	headValue = string(bValue)

	hb.crPos = hb.crPos[1:]
	hb.lfPos = hb.lfPos[1:]
	hb.colPos = hb.colPos[1:]

	ok = true

	return
}

// NewHTTPBuffer .
func NewHTTPBuffer() *HTTPBuffer {
	return &HTTPBuffer{
		crPos:  make([]int, 32)[0:0],
		lfPos:  make([]int, 32)[0:0],
		colPos: make([]int, 32)[0:0],
	}
}

func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}

func validMethod(method string) bool {
	/*
	     Method         = "OPTIONS"                ; Section 9.2
	                    | "GET"                    ; Section 9.3
	                    | "HEAD"                   ; Section 9.4
	                    | "POST"                   ; Section 9.5
	                    | "PUT"                    ; Section 9.6
	                    | "DELETE"                 ; Section 9.7
	                    | "TRACE"                  ; Section 9.8
	                    | "CONNECT"                ; Section 9.9
	                    | extension-method
	   extension-method = token
	     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

func parseRequestLine(line []byte) (method, requestURI, proto string, ok bool) {
	s1 := bytes.IndexByte(line, SPA)
	s2 := bytes.IndexByte(line[s1+1:], SPA)
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return string(line[:s1]), string(line[s1+1 : s2]), string(line[s2+1:]), true
}

func badStringError(what, val string) error { return fmt.Errorf("%s %q", what, val) }
