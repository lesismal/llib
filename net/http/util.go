package parser

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang/net/http/httpguts"
)

var (
	// ErrDataNotEnouth .
	ErrDataNotEnouth = errors.New("data not enougth")
	// ErrInvalidData .
	ErrInvalidData = errors.New("invalid data")
)

const (
	deleteHostHeader = true
	keepHostHeader   = false
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

func trim(s []byte) []byte {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	n := len(s)
	for n > i && (s[n-1] == ' ' || s[n-1] == '\t') {
		n--
	}
	return s[i:n]
}

// RFC 7234, section 5.4: Should treat
//	Pragma: no-cache
// like
//	Cache-Control: no-cache
func fixPragmaCacheControl(header http.Header) {
	if hp, ok := header["Pragma"]; ok && len(hp) > 0 && hp[0] == "no-cache" {
		if _, presentcc := header["Cache-Control"]; !presentcc {
			header["Cache-Control"] = []string{"no-cache"}
		}
	}
}
