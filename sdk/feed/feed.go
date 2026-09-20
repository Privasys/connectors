// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package feed is the change-feed contract the harness holds against every
// connector.
//
// The call is `{"since": "<cursor>", "wait_seconds": N}` and the answer is
// `{"changes": [...], "cursor": "<opaque>"}`. The harness long-polls: it
// parks one call for up to a minute and calls again with the cursor it was
// handed, so a quiet source costs nothing and a busy one is reported within
// seconds. The cursor is the connector's and the harness never reads into it.
//
// The helpers here are how a connector parks a call: until the provider's own
// event source wakes it (IMAP IDLE), or by asking the provider every so often
// (a CalDAV server has nothing to push). Either way the call returns as soon
// as something changed or when the wait ends, whichever comes first, and the
// wait is capped so a caller cannot camp on a connection.
package feed

import (
	"context"
	"encoding/json"
	"time"
)

// MaxWait bounds a long-poll. The caller long-polls; it does not camp.
const MaxWait = 60 * time.Second

// Request is the call.
type Request struct {
	Since       string `json:"since"`
	WaitSeconds int    `json:"wait_seconds"`
}

// Wait is how long the caller asked to wait, capped at MaxWait. Zero returns
// immediately.
func (r Request) Wait() time.Duration {
	return Clamp(time.Duration(r.WaitSeconds) * time.Second)
}

// Clamp caps a wait at MaxWait and floors it at zero.
func Clamp(wait time.Duration) time.Duration {
	if wait > MaxWait {
		return MaxWait
	}
	if wait < 0 {
		return 0
	}
	return wait
}

// Response is the answer. Changes is never null on the wire: an empty window
// is an empty list, so a client can range over it without a special case.
type Response struct {
	Changes []Change `json:"changes"`
	Cursor  string   `json:"cursor"`
}

// Change is one event from the source's own feed. Kind is the connector's
// vocabulary ("arrived", "removed", "changed" and the like); ID is what the
// connector's other tools take.
type Change struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// MarshalJSON keeps `changes` a list rather than null.
func (r Response) MarshalJSON() ([]byte, error) {
	type plain Response
	out := plain(r)
	if out.Changes == nil {
		out.Changes = []Change{}
	}
	return json.Marshal(out)
}

// Park holds until the source signals on wake, the wait ends, or the context
// is done. It reports whether it was woken, so the caller knows to look
// rather than to answer "nothing".
func Park(ctx context.Context, wait time.Duration, wake <-chan struct{}) bool {
	wait = Clamp(wait)
	if wait <= 0 {
		return false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-wake:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// Poll asks changed every interval until it answers true, the wait ends, or
// the context is done. It asks once straight away, so a change that happened
// before the call is reported without waiting an interval for it, and it
// never asks more often than interval whatever wait is. It reports whether
// something changed; an error from changed ends the poll and is returned.
func Poll(ctx context.Context, wait, interval time.Duration, changed func(context.Context) (bool, error)) (bool, error) {
	wait = Clamp(wait)
	if interval <= 0 {
		interval = time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		hit, err := changed(ctx)
		if err != nil || hit {
			return hit, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, nil
		}
		if remaining < interval {
			interval = remaining
		}
		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return false, nil
		}
	}
}
