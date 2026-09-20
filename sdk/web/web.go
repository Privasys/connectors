// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package web is the small amount of HTTP plumbing every connector shares:
// JSON in, JSON out, bounded bodies, and a log line that never carries what
// was in a request.
package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Privasys/connectors/sdk/caller"
)

// Decode parses a request body into v. An empty body is not an error: every
// tool takes an object and most fields are optional.
func Decode(body json.RawMessage, v any) error {
	if len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("malformed request body: %w", err)
	}
	return nil
}

// ReadLimited reads at most n bytes of the body and refuses more, so a caller
// cannot hand the service a body the size of its memory.
func ReadLimited(r *http.Request, n int64) (json.RawMessage, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	var total int64
	for {
		k, err := r.Body.Read(tmp)
		if k > 0 {
			total += int64(k)
			if total > n {
				return nil, errors.New("request body too large")
			}
			buf = append(buf, tmp[:k]...)
		}
		if err != nil {
			return buf, nil
		}
	}
}

// WriteJSON answers with one JSON document.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteErr answers with {"error": msg}.
func WriteErr(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// Logging records what was called for whom, and never what was in it. A
// connector's log must not become the copy of the data the design says nobody
// keeps.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sub := caller.ActingUser(r)
		if len(sub) > 8 {
			sub = sub[:8] + "…"
		}
		next.ServeHTTP(w, r)
		log.Printf("%s %s sub=%s %s", r.Method, r.URL.Path, sub, time.Since(start).Round(time.Millisecond))
	})
}
