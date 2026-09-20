// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package caller

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testApp = "590ebdc31b63401fbbb822d5f3886c5e"

// The header the runtime sets is the runtime's to choose, so both spellings
// are accepted; anything unrecognised must fail closed.
func TestPeerHeaderSpellings(t *testing.T) {
	for _, h := range []string{PeerAppHeader, PeerVerifiedHeader} {
		r := httptest.NewRequest(http.MethodPost, "/tools/x", nil)
		r.Header.Set(h, testApp)
		if got := App(r); got != "app:"+testApp {
			t.Errorf("%s: App = %q", h, got)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/tools/x", nil)
	r.Header.Set(PeerVerifiedHeader, "true")
	if got := App(r); got != "" {
		t.Errorf("a bare 'true' vouch names no app, got %q", got)
	}
	r = httptest.NewRequest(http.MethodPost, "/tools/x", nil)
	r.Header.Set(PeerAppHeader, "not-an-app-id")
	if got := App(r); got != "" {
		t.Errorf("a malformed peer id must not become one, got %q", got)
	}
	if got := App(httptest.NewRequest(http.MethodPost, "/tools/x", nil)); got != "" {
		t.Errorf("no header, no app, got %q", got)
	}
}

func TestActingUserIsTrimmedAndOptional(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/tools/x", nil)
	if ActingUser(r) != "" {
		t.Fatal("an absent subject must be empty, not defaulted")
	}
	r.Header.Set(SubjectHeader, "  user-1 ")
	if got := ActingUser(r); got != "user-1" {
		t.Fatalf("ActingUser = %q", got)
	}
}
