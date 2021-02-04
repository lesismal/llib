package bytes

import (
	"testing"
)

func TestBuffer(t *testing.T) {
	bufer := NewBuffer()
	bufer.Write([]byte("hel"))
	bufer.Write([]byte("lo world"))
	b, err := bufer.Read(5)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Fatal(string(b))
	}
	b, err = bufer.Read(1)
	if string(b) != " " {
		t.Fatal(string(b))
	}
	b, err = bufer.ReadAll()
	if string(b) != "world" {
		t.Fatal(string(b))
	}
}
