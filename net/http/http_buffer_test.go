package parser

import (
	"fmt"
	"testing"
)

func TestHTTPBuffer(t *testing.T) {
	requestData := []byte("POST /echo HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\nContent-Length: 5\r\nAccept-Encoding: gzip\r\n\r\nhello")

	hb := NewHTTPBuffer()

	hb.Push(requestData)
	// to do
	// host, path, version, code, err := hb.ReadURL()
	hb.ReadRequestLine()

	ret := map[string]string{
		"Host":            "localhost:8080",
		"Connection":      "close",
		"Content-Length":  "5",
		"Accept-Encoding": "gzip",
	}
	for {
		key, value, ok, err := hb.ReadHeader()
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			if v, ok := ret[key]; !ok || v != value {
				t.Fatal(fmt.Errorf("invalid key or value: [%v], value: [%v], retv: [%v]", key, value, v))
			}
			delete(ret, key)
		} else if len(ret) != 0 {
			t.Fatal(ret)
		} else {
			break
		}
	}
}
