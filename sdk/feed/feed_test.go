// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package feed

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestWaitIsCappedAtAMinute(t *testing.T) {
	if got := (Request{WaitSeconds: 600}).Wait(); got != MaxWait {
		t.Fatalf("a ten-minute wait should be capped, got %s", got)
	}
	if got := (Request{WaitSeconds: -5}).Wait(); got != 0 {
		t.Fatalf("a negative wait is zero, got %s", got)
	}
	if got := (Request{WaitSeconds: 20}).Wait(); got != 20*time.Second {
		t.Fatalf("an ordinary wait is kept, got %s", got)
	}
}

// The harness ranges over `changes`; a null there is a special case nobody
// should have to write.
func TestChangesIsNeverNull(t *testing.T) {
	b, err := json.Marshal(Response{Cursor: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"changes":[],"cursor":"c"}` {
		t.Fatalf("got %s", b)
	}
}

func TestParkWakesOnTheSignal(t *testing.T) {
	wake := make(chan struct{}, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		wake <- struct{}{}
	}()
	start := time.Now()
	if !Park(context.Background(), 5*time.Second, wake) {
		t.Fatal("the signal should have woken the park")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("woke far later than the signal")
	}
}

func TestParkReturnsWhenTheWaitEndsOrTheCallerLeaves(t *testing.T) {
	wake := make(chan struct{})
	if Park(context.Background(), 30*time.Millisecond, wake) {
		t.Fatal("nothing signalled, yet Park reports a wake")
	}
	if Park(context.Background(), 0, wake) {
		t.Fatal("a zero wait returns at once and reports no wake")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if Park(ctx, 10*time.Second, wake) {
		t.Fatal("a cancelled caller is not a wake")
	}
	if time.Since(start) > time.Second {
		t.Fatal("a cancelled caller should end the park at once")
	}
}

// Poll asks straight away, so a change that predates the call is reported
// without waiting an interval, and then at the interval until the wait ends.
func TestPollAsksAtOnceAndThenAtTheInterval(t *testing.T) {
	calls := 0
	hit, err := Poll(context.Background(), time.Second, time.Hour, func(context.Context) (bool, error) {
		calls++
		return true, nil
	})
	if err != nil || !hit || calls != 1 {
		t.Fatalf("an immediate change: hit=%v calls=%d err=%v", hit, calls, err)
	}

	calls = 0
	hit, err = Poll(context.Background(), 50*time.Millisecond, 10*time.Millisecond, func(context.Context) (bool, error) {
		calls++
		return calls >= 3, nil
	})
	if err != nil || !hit || calls != 3 {
		t.Fatalf("a change on the third look: hit=%v calls=%d err=%v", hit, calls, err)
	}

	calls = 0
	hit, err = Poll(context.Background(), 30*time.Millisecond, 10*time.Millisecond, func(context.Context) (bool, error) {
		calls++
		return false, nil
	})
	if err != nil || hit || calls < 2 {
		t.Fatalf("no change: hit=%v calls=%d err=%v", hit, calls, err)
	}

	boom := errors.New("provider down")
	if _, err := Poll(context.Background(), time.Second, time.Millisecond, func(context.Context) (bool, error) {
		return false, boom
	}); !errors.Is(err, boom) {
		t.Fatalf("an error ends the poll: %v", err)
	}
}
