// Copyright 2020 lesismal. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package concurrent

import (
	"sync"
)

var (
	_defaultBatch = NewBatch()
)

type call struct {
	done chan struct{}
	ret  interface{}
	err  error
}

// Batch .
type Batch struct {
	mux      sync.Mutex
	callings map[interface{}]*call
}

// Do .
func (batch *Batch) Do(key interface{}, f func() (interface{}, error)) (interface{}, error) {
	batch.mux.Lock()
	c, ok := batch.callings[key]
	if ok {
		batch.mux.Unlock()
		<-c.done
		return c.ret, c.err
	}

	c = &call{done: make(chan struct{})}
	batch.callings[key] = c
	defer close(c.done)

	batch.mux.Unlock()
	c.ret, c.err = f()

	batch.mux.Lock()
	delete(batch.callings, key)
	batch.mux.Unlock()

	return c.ret, c.err
}

// NewBatch .
func NewBatch() *Batch {
	return &Batch{callings: map[interface{}]*call{}}
}

// Do .
func Do(key interface{}, f func() (interface{}, error)) (interface{}, error) {
	return _defaultBatch.Do(key, f)
}
