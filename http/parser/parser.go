package parser

import (
	"net/http"

	"github.com/lesismal/llib/bytes"
)

const (
	// 1st line
	stateMethod int = iota
	stateURI
	stateProto

	// many header lines
	stateHeaders

	// header over, empty line
	stateBlankLine

	// body: chank or content-length
	stateBody
)

// Parser .
type Parser struct {
	data    []byte
	buffer  *bytes.Buffer
	request *http.Request
}

// Append .
func (p *Parser) Append(buf []byte) {
	p.data = append(p.data, buf...)
}

// Next .
func (p *Parser) Next() (*http.Request, bool, error) {

	return nil, false, nil
}

// New .
func New() *Parser {
	return &Parser{
		buffer: bytes.NewBuffer(),
	}
}
