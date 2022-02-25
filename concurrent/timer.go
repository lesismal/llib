// Copyright 2020 lesismal. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package concurrent

import (
	"container/heap"
	"log"
	"math"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

const (
	timeForever = time.Duration(math.MaxInt64)
)

func NewTimer(executor func(f func())) *Timer {
	if executor == nil {
		executor = func(f func()) {
			defer func() {
				err := recover()
				if err != nil {
					const size = 64 << 10
					buf := make([]byte, size)
					buf = buf[:runtime.Stack(buf, false)]
					log.Printf("timer exec timer failed: %v\n%v\n", err, *(*string)(unsafe.Pointer(&buf)))
				}
			}()
			f()
		}
	}
	return &Timer{
		trigger:   time.NewTimer(timeForever),
		chTimer:   make(chan struct{}, 1024),
		chCalling: make(chan struct{}, 1),
		executor:  executor,
	}
}

type Timer struct {
	mux sync.Mutex

	timers  timerHeap
	trigger *time.Timer
	chTimer chan struct{}

	callings  []func()
	chCalling chan struct{}
	executor  func(f func())
}

func (t *Timer) Start() {
	go t.loop()
}

func (t *Timer) Stop() {
	t.trigger.Stop()
	close(t.chTimer)
}

func (t *Timer) AtOnce(f func()) {
	if f != nil {
		t.mux.Lock()
		t.callings = append(t.callings, func() {
			t.executor(f)
		})
		t.mux.Unlock()
		select {
		case t.chCalling <- struct{}{}:
		default:
		}
	}
}

func (t *Timer) After(timeout time.Duration) <-chan time.Time {
	c := make(chan time.Time, 1)
	t.afterFunc(timeout, func() {
		t.executor(func() {
			c <- time.Now()
		})
	})
	return c
}

func (t *Timer) AfterFunc(timeout time.Duration, f func()) *htimer {
	ht := t.afterFunc(timeout, func() {
		t.executor(f)
	})
	return ht
}

func (t *Timer) afterFunc(timeout time.Duration, f func()) *htimer {
	t.mux.Lock()
	defer t.mux.Unlock()

	now := time.Now()
	it := &htimer{
		index:  len(t.timers),
		expire: now.Add(timeout),
		f:      f,
		parent: t,
	}
	heap.Push(&t.timers, it)
	if t.timers[0] == it {
		t.trigger.Reset(timeout)
	}

	return it
}

func (t *Timer) removeTimer(it *htimer) {
	t.mux.Lock()
	defer t.mux.Unlock()

	index := it.index
	if index < 0 || index >= len(t.timers) {
		return
	}

	if t.timers[index] == it {
		heap.Remove(&t.timers, index)
		if len(t.timers) > 0 {
			if index == 0 {
				t.trigger.Reset(time.Until(t.timers[0].expire))

			}
		} else {
			t.trigger.Reset(timeForever)
		}
	}
}

func (t *Timer) resetTimer(it *htimer) {
	t.mux.Lock()
	defer t.mux.Unlock()

	index := it.index
	if index < 0 || index >= len(t.timers) {
		return
	}

	if t.timers[index] == it {
		heap.Fix(&t.timers, index)
		if index == 0 || it.index == 0 {
			t.trigger.Reset(time.Until(t.timers[0].expire))
		}
	}
}

func (t *Timer) loop() {
	log.Printf("timer loop start")
	defer log.Printf("timer loop stop")

	for {
		select {
		case <-t.chCalling:
			for {
				t.mux.Lock()
				if len(t.callings) == 0 {
					t.callings = nil
					t.mux.Unlock()
					break
				}
				f := t.callings[0]
				t.callings = t.callings[1:]
				t.mux.Unlock()
				func() {
					defer func() {
						err := recover()
						if err != nil {
							const size = 64 << 10
							buf := make([]byte, size)
							buf = buf[:runtime.Stack(buf, false)]
							log.Printf("timer exec call failed: %v\n%v\n", err, *(*string)(unsafe.Pointer(&buf)))
						}
					}()
					f()
				}()
			}
		case <-t.trigger.C:
			for {
				t.mux.Lock()
				if t.timers.Len() == 0 {
					t.trigger.Reset(timeForever)
					t.mux.Unlock()
					break
				}
				now := time.Now()
				it := t.timers[0]
				if now.After(it.expire) {
					heap.Remove(&t.timers, it.index)
					t.mux.Unlock()
					it.f()
				} else {
					t.trigger.Reset(it.expire.Sub(now))
					t.mux.Unlock()
					break
				}
			}
		case <-t.chTimer:
			return
		}
	}
}

type htimer struct {
	index  int
	expire time.Time
	f      func()
	parent *Timer
}

func (it *htimer) Stop() {
	it.parent.removeTimer(it)
}

func (it *htimer) Reset(timeout time.Duration) {
	it.expire = time.Now().Add(timeout)
	it.parent.resetTimer(it)
}

type timerHeap []*htimer

func (h timerHeap) Len() int           { return len(h) }
func (h timerHeap) Less(i, j int) bool { return h[i].expire.Before(h[j].expire) }
func (h timerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *timerHeap) Push(x interface{}) {
	*h = append(*h, x.(*htimer))
	n := len(*h)
	(*h)[n-1].index = n - 1
}
func (h *timerHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*h = old[0 : n-1]
	return x
}
