package parser

import (
	"log"
	"testing"
)

func TestParser(t *testing.T) {
	requestData := []byte("POST /echo HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\nContent-Length: 5\r\nAccept-Encoding: gzip\r\n\r\nhello")

	parser := New()

	for i := 0; i < len(requestData)-6; i++ {
		parser.Append(requestData[i : i+1])
		_, ok, err := parser.ReadRequest()
		if err != nil {
			t.Fatalf("ReadRequest failed: %v", err)
		}
		if ok {
			t.Fatalf("ReadRequest failed: %v", err)
		}
	}

	parser.Append(requestData[len(requestData)-6:])
	request, ok, err := parser.ReadRequest()
	if ok {
		log.Printf("ReadRequest success error: %v, %v, %v, %v, %+v", err, request.Method, request.URL.Path, request.Proto, request.Header)
	} else {
		t.Fatalf("ReadRequest failed: %v", err)
	}
}
