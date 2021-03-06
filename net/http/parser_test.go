package parser

import (
	"log"
	"testing"
)

func TestParser(t *testing.T) {

	parser := New()

	for i := 0; i < 3; i++ {
		requestData := []byte("POST /echo HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close \r\n Content-Length :  5\r\nAccept-Encoding : gzip \r\n\r\nhello")

		for i := 0; i < len(requestData)-6; i++ {
			// parser.Append(requestData[i : i+1])
			_, ok, err := parser.ReadRequest(requestData[i : i+1])
			if err != nil {
				t.Fatalf("ReadRequest failed: %v", err)
			}
			if ok {
				t.Fatalf("ReadRequest failed: %v", err)
			}
		}

		// parser.Append(requestData[len(requestData)-6:])
		request, ok, err := parser.ReadRequest(requestData[len(requestData)-6:])
		if ok {
			log.Printf("ReadRequest success error: %v, %v, %v, %v, %v, %v, %v, %v, %+v", err, request.Method, request.URL.Path, request.Proto, request.URL.Host, request.URL.Path, request.URL.RawPath, request.ContentLength, request.Header)
		} else {
			t.Fatalf("ReadRequest failed: %v", err)
		}
	}
}
