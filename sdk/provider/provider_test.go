// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package provider

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestWellKnownDomainsNeedNoLookup(t *testing.T) {
	r := &Resolver{LookupMX: func(context.Context, string) ([]*net.MX, error) {
		t.Fatal("looked up a well-known domain")
		return nil, nil
	}}
	for addr, want := range map[string]Provider{
		"Alice@Gmail.com":  Google,
		"bob@hotmail.fr":   Microsoft,
		"carol@outlook.com": Microsoft,
		"no-at-sign":       Other,
		"dan@":             Other,
	} {
		if got := r.Of(context.Background(), addr); got != want {
			t.Errorf("%s: %s, want %s", addr, got, want)
		}
	}
}

func TestCustomDomainsAreReadFromMX(t *testing.T) {
	mx := map[string][]*net.MX{
		"workspace.example": {{Host: "aspmx.l.google.com."}},
		"tenant.example":    {{Host: "tenant-example.mail.protection.outlook.com."}},
		"self.example":      {{Host: "mail.self.example."}},
	}
	r := &Resolver{LookupMX: func(_ context.Context, d string) ([]*net.MX, error) {
		if m, ok := mx[d]; ok {
			return m, nil
		}
		return nil, errors.New("no such domain")
	}}
	for addr, want := range map[string]Provider{
		"a@workspace.example": Google,
		"b@tenant.example":    Microsoft,
		"c@self.example":      Other,
		"d@unknown.example":   Other,
	} {
		if got := r.Of(context.Background(), addr); got != want {
			t.Errorf("%s: %s, want %s", addr, got, want)
		}
	}
}

func TestNilResolverIsTheTableAlone(t *testing.T) {
	var r *Resolver
	if r.Of(context.Background(), "a@gmail.com") != Google || r.Of(context.Background(), "a@x.example") != Other {
		t.Fatal("a nil resolver must answer from the table")
	}
	if Google.Name() != "Google" || Microsoft.Name() != "Microsoft" || Other.Name() != "" {
		t.Fatal("names")
	}
}
