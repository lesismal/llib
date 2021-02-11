package bytes

import (
	"errors"
)

var (
	ErrInvalidLength = errors.New("invalid length")
	ErrNotEnougth    = errors.New("bytes not enougth")
)

// Buffer .
type Buffer struct {
	total   int
	buffers [][]byte
}

// Len .
func (bb *Buffer) Len() int {
	return bb.total
}

// ReadN .
func (bb *Buffer) ReadN(l int) ([]byte, error) {
	if l < 0 {
		return nil, ErrInvalidLength
	}
	if bb.total < l {
		return nil, ErrNotEnougth
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

// HeadN .
func (bb *Buffer) HeadN(l int) ([]byte, error) {
	if l < 0 {
		return nil, ErrInvalidLength
	}
	if bb.total < l {
		return nil, ErrNotEnougth
	}

	if len(bb.buffers[0]) >= l {
		return bb.buffers[0][:l], nil
	}

	ret := make([]byte, l)

	copied := 0
	for i := 0; l > 0; i++ {
		buf := bb.buffers[i]
		if len(buf) >= l {
			copy(ret[copied:], buf[:l])
			return ret, nil
		} else {
			copy(ret[copied:], buf)
			l -= len(buf)
			copied += len(buf)
		}
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

// Reset .
func (bb *Buffer) Reset() {
	bb.buffers = nil
	bb.total = 0
}

// NewBuffer .
func NewBuffer() *Buffer {
	return &Buffer{}
}
