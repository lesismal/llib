// Copyright 2020 lesismal. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package concurrent

import (
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBatch(t *testing.T) {
	var wg sync.WaitGroup
	var count int32
	var timewait = time.Second / 10
	batchCall := func() (interface{}, error) {
		atomic.AddInt32(&count, 1)
		time.Sleep(timewait)
		return time.Now().Format("2006/01/02 15:04:05.000"), nil
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ret, err := Do(3, batchCall)
			log.Println("Batch().Do():", id, ret, err)
		}(2)
	}
	wg.Wait()
	if n := atomic.LoadInt32(&count); n != 1 {
		t.Fatalf("Invalid count: %v", n)
	}

	func(id int) {
		ret, err := Do(3, batchCall)
		log.Println("Batch().Do():", id, ret, err)
	}(1)

	func(id int) {
		ret, err := Do(3, batchCall)
		log.Println("Batch().Do():", id, ret, err)
	}(3)

	if n := atomic.LoadInt32(&count); n != 3 {
		t.Fatalf("Invalid count: %v", n)
	}
}
