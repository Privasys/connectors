// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package oauth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Two providers on one kind: each start goes to the provider named, each
// callback finds the flow that started it, and a state from neither is
// refused.
func TestMultiDispatchesStartAndCallback(t *testing.T) {
	a, b := newFakeProvider(t), newFakeProvider(t)
	m := NewMulti("files.cloud")
	fa := m.Add("alpha", Provider{Name: "Alpha", AuthURL: a.srv.URL + "/auth", TokenURL: a.srv.URL + "/token", Scopes: []string{"s"}})
	fb := m.Add("beta", Provider{Name: "Beta", AuthURL: b.srv.URL + "/auth", TokenURL: b.srv.URL + "/token", Scopes: []string{"s"}})
	fa.HTTPClient, fb.HTTPClient = a.srv.Client(), b.srv.Client()
	fa.SetClient("cid", "csecret")
	fb.SetClient("cid", "csecret")
	mux := http.NewServeMux()
	m.Routes(mux)

	// The button names the provider on the start URL.
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Host = "files.apps.example"
	prop := m.SchemaProperty(req, "beta")
	x := prop["x-privasys-oauth"].(map[string]string)
	if x["provider"] != "Beta" || x["start_url"] != "https://files.apps.example"+StartPath+"?kind=files.cloud&provider=beta" {
		t.Fatalf("schema property: %+v", x)
	}
	if m.SchemaProperty(req, "gamma") != nil || m.Flow("gamma") != nil {
		t.Fatal("an unknown slug has no button and no flow")
	}

	start := StartPath + "?kind=files.cloud&redirect_uri=privasys-wallet%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh12345678"
	if w := get(mux, start); w.Code != http.StatusNotFound {
		t.Fatalf("no provider named: %d %s", w.Code, w.Body)
	}
	if w := get(mux, start+"&provider=gamma"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown provider: %d", w.Code)
	}

	w := get(mux, start+"&provider=beta")
	if w.Code != http.StatusFound {
		t.Fatalf("start beta: %d %s", w.Code, w.Body)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if !strings.HasPrefix(loc.String(), b.srv.URL+"/auth?") {
		t.Fatalf("beta's start goes to beta: %s", loc)
	}
	_, _ = http.Get(loc.String())
	state := loc.Query().Get("state")

	// Alpha does not own beta's state; the callback still finds beta.
	if fa.owns(state) || !fb.owns(state) {
		t.Fatal("ownership of the state")
	}
	w = get(mux, CallbackPath+"?code="+b.code+"&state="+state)
	if w.Code != http.StatusFound {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	back, _ := url.Parse(w.Header().Get("Location"))
	grant := back.Query().Get("grant")
	if grant == "" {
		t.Fatalf("the wallet gets the grant: %s", back)
	}
	if _, ok := fa.Redeem(grant); ok {
		t.Fatal("the grant belongs to beta's flow, not alpha's")
	}
	if got, ok := fb.Redeem(grant); !ok || got.AccessToken != "at-1" {
		t.Fatalf("redeem at beta: %+v %v", got, ok)
	}
	// A state nobody issued, and an empty one.
	if w := get(mux, CallbackPath+"?code=x&state=nobody"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown state: %d", w.Code)
	}
	if w := get(mux, CallbackPath+"?code=x"); w.Code != http.StatusBadRequest {
		t.Fatalf("no state: %d", w.Code)
	}
}

func TestMultiRefusesABadSlug(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a slug with a capital letter should panic at registration")
		}
	}()
	NewMulti("k").Add("Alpha", Provider{})
}
