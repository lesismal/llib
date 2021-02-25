package bytes

import (
	"errors"
)

var (
	errDataNotEnouth = errors.New("data not enougth")
	errInvalidData   = errors.New("invalid data")
)

const (
	// CR .
	CR = '\r'
	// LF .
	LF = '\n'
	// COL .
	COL = ':'
)

const (
	// LineTypeHost .
	LineTypeHost = 1
	// LineTypeHeader .
	LineTypeHeader = 2
	// LineTypeBody .
	LineTypeBody = 3
)

// HTTPBuffer .
type HTTPBuffer struct {
	Buffer
	crPos    []int
	lfPos    []int
	colPos   []int
	offset   int
	colExist bool
}

// Push .
func (hb *HTTPBuffer) Push(b []byte) {
	var c byte
	var l = hb.Len()
	for i := 0; i < len(b); i++ {
		c = b[i]
		switch c {
		case CR:
			hb.crPos = append(hb.crPos, hb.offset+l+i)
		case LF:
			hb.lfPos = append(hb.lfPos, hb.offset+l+i)
			hb.colExist = false
		case COL:
			if !hb.colExist {
				hb.colExist = true
				hb.colPos = append(hb.colPos, hb.offset+l+i)
			}
		default:
		}
	}
	hb.Buffer.Push(b)
}

// ReadURL .
func (hb *HTTPBuffer) ReadURL() (host string, path string, version string, code string, err error) {
	if len(hb.crPos) < 1 || len(hb.lfPos) < 1 {
		err = errDataNotEnouth
		return
	}
	if hb.crPos[0]+1 != hb.lfPos[0] {
		err = errInvalidData
		return
	}

	l := hb.lfPos[0] + 1 - hb.offset
	hb.Pop(l)

	hb.offset += l

	hb.crPos = hb.crPos[1:]
	hb.lfPos = hb.lfPos[1:]

	return
}

// ReadHeader .
func (hb *HTTPBuffer) ReadHeader() (headKey string, headValue string, ok bool, err error) {
	if len(hb.crPos) < 1 || len(hb.lfPos) < 1 {
		err = errDataNotEnouth
		return
	}
	if hb.crPos[0]+1 != hb.lfPos[0] {
		err = errInvalidData
		return
	}
	if hb.crPos[0]-hb.offset == 0 {
		hb.Pop(2)
		hb.offset += 2
		ok = false
		return
	}

	if len(hb.colPos) == 0 {
		err = errInvalidData
		return
	}

	// log.Printf("Before ReadHeader: [%v]", string(hb.buffers[0]))

	var bKey, bValue []byte
	l := hb.colPos[0] - hb.offset
	bKey, err = hb.Pop(l)
	// log.Printf("--- bKey: [%v] [%v]", string(bKey), len(bKey))
	hb.Pop(1)
	hb.offset += (l + 1)
	l = hb.crPos[0] - hb.colPos[0] - 1
	bValue, err = hb.Pop(l)
	// log.Printf("--- bValue: [%v] [%v] [%v] [%v] [%v]", string(bValue), hb.crPos[0], hb.colPos[0], hb.offset, l)
	hb.Pop(2)
	hb.offset += (l + 2)

	for i := 0; i < len(bKey); i++ {
		if bKey[i] != ' ' {
			bKey = bKey[i:]
			break
		}
	}
	for i := len(bKey) - 1; i >= 0; i-- {
		if bKey[i] != ' ' {
			bKey = bKey[:i+1]
			break
		}
	}
	for i := 0; i < len(bValue); i++ {
		if bValue[i] != ' ' {
			bValue = bValue[i:]
			break
		}
	}
	for i := len(bValue) - 1; i >= 0; i-- {
		if bValue[i] != ' ' {
			bValue = bValue[:i+1]
			break
		}
	}
	headKey = string(bKey)
	headValue = string(bValue)

	hb.crPos = hb.crPos[1:]
	hb.lfPos = hb.lfPos[1:]
	hb.colPos = hb.colPos[1:]

	ok = true

	// if len(hb.buffers) > 0 {
	// 	log.Printf("After ReadHeader: [%v]", string(hb.buffers[0]))
	// } else {
	// 	log.Printf("After ReadHeader: [null]")
	// }
	return
}

// NewHTTPBuffer .
func NewHTTPBuffer() *HTTPBuffer {
	return &HTTPBuffer{
		crPos:  make([]int, 32)[0:0],
		lfPos:  make([]int, 32)[0:0],
		colPos: make([]int, 32)[0:0],
	}
}
