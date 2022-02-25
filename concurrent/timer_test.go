package concurrent

import (
	"testing"
	"time"
)

func checkTolerance(t *testing.T, t0 time.Time, wait, tolerance time.Duration) {
	used := time.Since(t0) - wait
	if used < 0 {
		used = -used
	}
	if used > tolerance {
		t.Fatalf("used %v, expect %v", used, tolerance)
	}
}
func TestTimer(t *testing.T) {
	timer := NewTimer(nil)
	timer.Start()
	defer timer.Stop()

	wait := 100 * time.Millisecond
	tolerance := 3 * time.Millisecond

	{
		t0 := time.Now()
		<-timer.After(wait)
		checkTolerance(t, t0, wait, tolerance)
	}

	{
		t0 := time.Now()
		chDone := make(chan struct{}, 1)
		timer.AfterFunc(wait, func() {
			chDone <- struct{}{}
		})
		<-chDone
		checkTolerance(t, t0, wait, tolerance)
	}

	{
		t0 := time.Now()
		chDone := make(chan struct{}, 1)
		timer.AtOnce(func() {
			chDone <- struct{}{}
		})
		<-chDone
		checkTolerance(t, t0, 0, tolerance)
	}
}
