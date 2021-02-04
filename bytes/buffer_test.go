package bytes

import (
	"testing"
)

func TestBuffer(t *testing.T) {
	buffer := NewBuffer()
	buffer.Write([]byte("hel"))
	buffer.Write([]byte("lo world"))
	b, err := buffer.ReadN(5)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Fatal(string(b))
	}
	b, err = buffer.ReadN(1)
	if string(b) != " " {
		t.Fatal(string(b))
	}
	b, err = buffer.ReadAll()
	if string(b) != "world" {
		t.Fatal(string(b))
	}

	buffer.Reset()

	buffer.Write([]byte("hel"))
	buffer.Write([]byte("lo world"))
	b, err = buffer.ReadN(5)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Fatal(string(b))
	}
	b, err = buffer.ReadN(1)
	if string(b) != " " {
		t.Fatal(string(b))
	}
	b, err = buffer.ReadAll()
	if string(b) != "world" {
		t.Fatal(string(b))
	}
}
