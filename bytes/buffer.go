package bytes

import (
	"errors"
)

// Buffer .
type Buffer struct {
	total   int
	buffers [][]byte
}

// Length .
func (bb *Buffer) Length() int {
	return bb.total
}

// Read .
func (bb *Buffer) Read(l int) ([]byte, error) {
	if len(bb.buffers) == 0 {
		return nil, errors.New("empty Buffer")
	}
	if bb.total < l {
		return nil, errors.New("bytes not enougth")
	}
	var buf = bb.buffers[0]
	if len(buf) >= l {
		ret := buf[:l]
		bb.buffers[0] = bb.buffers[0][l:]
		if len(bb.buffers[0]) == 0 {
			bb.buffers = bb.buffers[1:]
		}
		return ret, nil
	}

	var ret = make([]byte, l)[0:0]
	for l > 0 {
		if len(buf) >= l {
			ret = append(ret, buf[:l]...)
			bb.buffers[0] = bb.buffers[0][l:]
			if len(bb.buffers[0]) == 0 {
				bb.buffers = bb.buffers[1:]
			}
			return ret, nil
		}
		ret = append(ret, buf...)
		bb.buffers = bb.buffers[1:]
		l -= len(buf)
		buf = bb.buffers[0]
	}
	return ret, nil
}

// ReadAll .
func (bb *Buffer) ReadAll() ([]byte, error) {
	if len(bb.buffers) == 0 {
		return nil, nil
	}

	buf := bb.buffers[0]
	for i := 1; i < len(bb.buffers); i++ {
		buf = append(buf, bb.buffers[i]...)
	}
	bb.buffers = nil

	return buf, nil
}

// Write .
func (bb *Buffer) Write(b []byte) {
	if len(b) == 0 {
		return
	}
	bb.buffers = append(bb.buffers, b)
	bb.total += len(b)
}

// NewBuffer .
func NewBuffer() *Buffer {
	return &Buffer{}
}
