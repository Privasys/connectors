// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package holder

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeVerifier struct {
	sub string
	err error
}

func (f fakeVerifier) Verify(context.Context, string) (*Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &Identity{Sub: f.sub}, nil
}

// The relay-asserted subject is a holder, and it wins over a bearer: the
// runtime stripped any inbound value first, so it can only have been set by
// the runtime.
func TestRelaySubjectIsTheHolder(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	r.Header.Set(RelaySubjectHeader, "user-1")
	r.Header.Set("Authorization", "Bearer x")
	if got := Of(r, fakeVerifier{sub: "user-2"}); got != "user-1" {
		t.Fatalf("Of = %q, want the relay's subject", got)
	}
}

// A bearer is only a holder once it VERIFIES. With no verifier installed,
// which is the state before configure names an issuer, every bearer is
// refused rather than taken at face value; so is one the verifier rejects.
func TestBearerNeedsAVerifierThatAccepts(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	r.Header.Set("Authorization", "Bearer x")
	if got := Of(r, nil); got != "" {
		t.Fatalf("a bearer with no verifier was a holder: %q", got)
	}
	if got := Of(r, fakeVerifier{err: errors.New("bad")}); got != "" {
		t.Fatalf("an unverifiable bearer was a holder: %q", got)
	}
	if got := Of(r, fakeVerifier{sub: "user-1"}); got != "user-1" {
		t.Fatalf("a verified bearer names the holder, got %q", got)
	}
}

// The defect this locks out: the header the CALLING APP writes must never
// establish a holder, whatever else the request carries.
func TestActingUserHeaderIsNotAHolder(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	r.Header.Set("X-Privasys-On-Behalf-Of", "somebody-else")
	r.Header.Set("X-Privasys-Peer-App-Id", "590ebdc31b63401fbbb822d5f3886c5e")
	if got := Of(r, fakeVerifier{sub: "never-asked"}); got != "" {
		t.Fatalf("an app's own assertion established a holder: %q", got)
	}
}
