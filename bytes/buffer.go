package bytes

import (
	"errors"
)

var (
	ErrInvalidLength   = errors.New("invalid length")
	ErrInvalidPosition = errors.New("invalid position")
	ErrNotEnougth      = errors.New("bytes not enougth")
)

// Buffer .
type Buffer struct {
	total     int
	buffers   [][]byte
	head      []byte
	onRelease func(b []byte)
}

// Len .
func (bb *Buffer) Len() int {
	return bb.total
}

// Push .
func (bb *Buffer) Push(b []byte) {
	if len(b) == 0 {
		return
	}
	bb.buffers = append(bb.buffers, b)
	bb.total += len(b)
	if len(bb.buffers) == 1 {
		bb.head = b
	}
}

// Pop .
func (bb *Buffer) Pop(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrInvalidLength
	}
	if bb.total < n {
		return nil, ErrNotEnougth
	}
	var buf = bb.buffers[0]
	if len(buf) >= n {
		ret := buf[:n]
		bb.buffers[0] = bb.buffers[0][n:]
		if len(bb.buffers[0]) == 0 {
			switch len(bb.buffers) {
			case 1:
				bb.buffers = nil
			default:
				bb.buffers = bb.buffers[1:]
			}
			bb.releaseHead()
		}
		return ret, nil
	}

	var ret = make([]byte, n)[0:0]
	for n > 0 {
		if len(buf) >= n {
			ret = append(ret, buf[:n]...)
			bb.buffers[0] = bb.buffers[0][n:]
			if len(bb.buffers[0]) == 0 {
				switch len(bb.buffers) {
				case 1:
					bb.buffers = nil
				default:
					bb.buffers = bb.buffers[1:]
				}
				bb.releaseHead()
			}
			return ret, nil
		}
		ret = append(ret, buf...)
		switch len(bb.buffers) {
		case 1:
			bb.buffers = nil
		default:
			bb.buffers = bb.buffers[1:]
		}
		bb.releaseHead()
		n -= len(buf)
		buf = bb.buffers[0]
	}
	return ret, nil
}

// Append .
func (bb *Buffer) Append(b []byte) {
	if len(b) == 0 {
		return
	}

	n := len(bb.buffers)

	if n == 0 {
		bb.buffers = append(bb.buffers, b)
		return
	}
	bb.buffers[n-1] = append(bb.buffers[n-1], b...)
	bb.total += len(b)
}

// Head .
func (bb *Buffer) Head(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrInvalidLength
	}
	if bb.total < n {
		return nil, ErrNotEnougth
	}

	if len(bb.buffers[0]) >= n {
		return bb.buffers[0][:n], nil
	}

	ret := make([]byte, n)

	copied := 0
	for i := 0; n > 0; i++ {
		buf := bb.buffers[i]
		if len(buf) >= n {
			copy(ret[copied:], buf[:n])
			return ret, nil
		} else {
			copy(ret[copied:], buf)
			n -= len(buf)
			copied += len(buf)
		}
	}

	return ret, nil
}

// Sub .
func (bb *Buffer) Sub(from, to int) ([]byte, error) {
	if from < 0 || to < 0 || to < from {
		return nil, ErrInvalidPosition
	}
	if bb.total < to {
		return nil, ErrNotEnougth
	}

	if len(bb.buffers[0]) >= to {
		return bb.buffers[0][from:to], nil
	}

	n := to - from
	ret := make([]byte, n)
	copied := 0
	for i := 0; n > 0; i++ {
		buf := bb.buffers[i]
		if len(buf) >= from+n {
			copy(ret[copied:], buf[from:from+n])
			return ret, nil
		} else {
			if len(buf) > from {
				if from > 0 {
					buf = buf[from:]
					from = 0
				}
				copy(ret[copied:], buf)
				copied += len(buf)
				n -= len(buf)
			} else {
				from -= len(buf)
			}
		}
	}

	return ret, nil
}

// Write .
func (bb *Buffer) Write(b []byte) {
	bb.Push(b)
}

// Read .
func (bb *Buffer) Read(n int) ([]byte, error) {
	return bb.Pop(n)
}

// ReadAll .
func (bb *Buffer) ReadAll() ([]byte, error) {
	n := len(bb.buffers)
	if n == 0 {
		return nil, nil
	}

	ret := []byte{}
	for i := 0; i < n; i++ {
		ret = append(ret, bb.buffers[0]...)
		switch len(bb.buffers) {
		case 1:
			bb.buffers = nil
		default:
			bb.buffers = bb.buffers[1:]
		}
		bb.releaseHead()
	}
	bb.buffers = nil

	return ret, nil
}

// Reset .
func (bb *Buffer) Reset() {
	bb.buffers = nil
	bb.total = 0
}

func (bb *Buffer) OnRelease(onRelease func(b []byte)) {
	bb.onRelease = onRelease
}

func (bb *Buffer) releaseHead() {
	if bb.head != nil && bb.onRelease != nil {
		bb.onRelease(bb.head)
	}
	if len(bb.buffers) > 0 {
		bb.head = bb.buffers[0]
	} else {
		bb.head = nil
	}
}

// NewBuffer .
func NewBuffer() *Buffer {
	return &Buffer{}
}
