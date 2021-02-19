package bytes

import (
	"testing"
)

func TestBuffer(t *testing.T) {
	buffer := NewBuffer()
	buffer.Write([]byte("hel"))
	buffer.Write([]byte("lo world"))
	b, err := buffer.Read(5)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Fatal(string(b))
	}
	b, err = buffer.Read(1)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != " " {
		t.Fatal(string(b))
	}
	b, err = buffer.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "world" {
		t.Fatal(string(b))
	}

	buffer.Reset()

	buffer.Write([]byte("hel"))
	buffer.Write([]byte("lo world"))
	b, err = buffer.Read(5)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Fatal(string(b))
	}
	b, err = buffer.Read(1)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != " " {
		t.Fatal(string(b))
	}
	b, err = buffer.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "world" {
		t.Fatal(string(b))
	}

	buffer.Reset()

	buffer.Append([]byte("hello"))
	buffer.Append([]byte(" world"))
	if string(buffer.buffers[0]) != "hello world" {
		t.Fatal(string(buffer.buffers[0]))
	}
	b, err = buffer.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello world" {
		t.Fatal(string(b))
	}

	buffer.Reset()

	str := "hello world"
	buffer.Push([]byte("hello "))
	buffer.Push([]byte("world"))
	for i := 0; i < len(str); i++ {
		for j := i; j < len(str); j++ {
			sub, err := buffer.Sub(i, j)
			if err != nil {
				t.Fatal(err)
			}
			if string(sub) != string([]byte(str)[i:j]) {
				t.Fatalf("[%v:%v] %v != %v", i, j, string(sub), string([]byte(str)[i:j]))
			}
		}
	}
	b, err = buffer.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello world" {
		t.Fatal(string(b))
	}

	buffer.Reset()

	buffer.Push([]byte("hello "))
	buffer.Push([]byte("world"))
	if string(buffer.head) != "hello " {
		t.Fatal(string(buffer.head))
	}
	buffer.Pop(1)
	if string(buffer.head) != "hello " {
		t.Fatal(string(buffer.head))
	}
	buffer.Pop(5)
	if string(buffer.head) != "world" {
		t.Fatal(string(buffer.head))
	}
	buffer.ReadAll()
	if len(buffer.head) != 0 {
		t.Fatal(string(buffer.head))
	}
}
