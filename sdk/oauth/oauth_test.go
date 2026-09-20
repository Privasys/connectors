// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeProvider is an authorisation server that remembers what it was asked
// and checks the exchange the way a real one does: the code it issued, the
// client secret, the PKCE verifier against the challenge, and the redirect
// URI it saw.
type fakeProvider struct {
	srv       *httptest.Server
	authQuery url.Values
	code      string
	challenge string
	redirect  string
	refuse    bool
	refreshes int
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	p := &fakeProvider{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		p.authQuery = r.URL.Query()
		p.challenge = p.authQuery.Get("code_challenge")
		p.redirect = p.authQuery.Get("redirect_uri")
		p.code = "code-" + p.authQuery.Get("state")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "csecret" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if p.refuse || r.Form.Get("code") != p.code || r.Form.Get("redirect_uri") != p.redirect {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge {
				http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`, http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600,
			})
		case "refresh_token":
			p.refreshes++
			if p.refuse || r.Form.Get("refresh_token") != "rt-1" {
				http.Error(w, `{"error":"invalid_grant","error_description":"Token has been revoked."}`, http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-2", "token_type": "Bearer", "expires_in": 3600})
		default:
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		}
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func newFlow(t *testing.T, p *fakeProvider) (*Flow, *http.ServeMux) {
	t.Helper()
	f := New(Provider{
		Name: "Example", AuthURL: p.srv.URL + "/auth", TokenURL: p.srv.URL + "/token",
		Scopes:     []string{"https://example.test/auth/calendar"},
		AuthParams: map[string]string{"access_type": "offline", "prompt": "consent"},
	}, "calendar.events")
	f.HTTPClient = p.srv.Client()
	f.SetClient("cid", "csecret")
	m := http.NewServeMux()
	f.Routes(m)
	return f, m
}

func get(m *http.ServeMux, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = "cal.apps.example"
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	return w
}

const startOK = StartPath + "?kind=calendar.events&redirect_uri=privasys-wallet%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh12345678"

// The whole round trip: start, the provider, the callback, the wallet's
// grant, the redeem, once.
func TestStartCallbackRedeem(t *testing.T) {
	p := newFakeProvider(t)
	f, m := newFlow(t, p)
	f.Identify = func(_ context.Context, tk Tokens) (string, error) {
		if tk.AccessToken != "at-1" {
			return "", errors.New("wrong token")
		}
		return "me@example.test", nil
	}

	w := get(m, startOK)
	if w.Code != http.StatusFound {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), p.srv.URL+"/auth?") {
		t.Fatalf("start should send the browser to the provider: %v", w.Header().Get("Location"))
	}
	q := loc.Query()
	for k, want := range map[string]string{
		"client_id": "cid", "response_type": "code", "scope": "https://example.test/auth/calendar",
		"redirect_uri": "https://cal.apps.example/v1/oauth/callback", "code_challenge_method": "S256",
		"access_type": "offline", "prompt": "consent",
	} {
		if q.Get(k) != want {
			t.Errorf("auth url %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Get("state") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("auth url needs state and challenge: %s", loc)
	}
	if strings.Contains(loc.String(), "csecret") {
		t.Fatal("the client secret is in the browser's URL")
	}
	// The provider records the request and issues a code.
	_, _ = http.Get(loc.String())

	w = get(m, CallbackPath+"?code="+p.code+"&state="+q.Get("state"))
	if w.Code != http.StatusFound {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	back, _ := url.Parse(w.Header().Get("Location"))
	if back.Scheme != "privasys-wallet" || back.Host != "setup" || back.Path != "/callback" {
		t.Fatalf("callback should send the browser back to the wallet: %s", back)
	}
	if back.Query().Get("nonce") != "abcdefgh12345678" || back.Query().Get("grant") == "" || back.Query().Get("error") != "" {
		t.Fatalf("the wallet gets the grant and its nonce: %s", back)
	}
	for _, never := range []string{"at-1", "rt-1", q.Get("state"), p.code} {
		if strings.Contains(back.String(), never) {
			t.Fatalf("%q travelled to the wallet: %s", never, back)
		}
	}

	got, ok := f.Redeem(back.Query().Get("grant"))
	if !ok || got.AccessToken != "at-1" || got.RefreshToken != "rt-1" || got.Identity != "me@example.test" || got.Expiry.IsZero() {
		t.Fatalf("redeem: %+v %v", got, ok)
	}
	if _, ok := f.Redeem(back.Query().Get("grant")); ok {
		t.Fatal("a grant code is single use")
	}
	// The state is single use too: replaying the callback is refused.
	if w := get(m, CallbackPath+"?code="+p.code+"&state="+q.Get("state")); w.Code != http.StatusBadRequest {
		t.Fatalf("a replayed state: %d", w.Code)
	}
}

func TestStartRefusesBadArguments(t *testing.T) {
	p := newFakeProvider(t)
	_, m := newFlow(t, p)
	for name, target := range map[string]string{
		"other kind":     StartPath + "?kind=mail.mailbox&redirect_uri=w%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh12345678",
		"https redirect": StartPath + "?kind=calendar.events&redirect_uri=https%3A%2F%2Fevil.example%2Fsetup%2Fcallback&nonce=abcdefgh12345678",
		"http redirect":  StartPath + "?kind=calendar.events&redirect_uri=http%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh12345678",
		"other path":     StartPath + "?kind=calendar.events&redirect_uri=w%3A%2F%2Fsetup%2Fother&nonce=abcdefgh12345678",
		"query on it":    StartPath + "?kind=calendar.events&redirect_uri=w%3A%2F%2Fsetup%2Fcallback%3Fx%3D1&nonce=abcdefgh12345678",
		"bad scheme":     StartPath + "?kind=calendar.events&redirect_uri=W_x%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh12345678",
		"short nonce":    StartPath + "?kind=calendar.events&redirect_uri=w%3A%2F%2Fsetup%2Fcallback&nonce=abc",
		"unsafe nonce":   StartPath + "?kind=calendar.events&redirect_uri=w%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh%2F12345678",
		"no nonce":       StartPath + "?kind=calendar.events&redirect_uri=w%3A%2F%2Fsetup%2Fcallback",
	} {
		if w := get(m, target); w.Code == http.StatusFound {
			t.Errorf("%s should have been refused: %d", name, w.Code)
		}
	}
	// Without a client there is nowhere to send anyone.
	f := New(Provider{Name: "X", AuthURL: "https://x/a", TokenURL: "https://x/t"}, "calendar.events")
	m2 := http.NewServeMux()
	f.Routes(m2)
	if w := get(m2, startOK); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no client: %d", w.Code)
	}
}

// The provider saying no, an exchange that fails, and a probe that fails all
// send the wallet back with a short reason and no grant. An unknown state has
// nowhere to go and says so.
func TestCallbackFailures(t *testing.T) {
	p := newFakeProvider(t)
	f, m := newFlow(t, p)

	start := func() string {
		w := get(m, startOK)
		loc, _ := url.Parse(w.Header().Get("Location"))
		_, _ = http.Get(loc.String())
		return loc.Query().Get("state")
	}
	errorOf := func(w *httptest.ResponseRecorder) string {
		if w.Code != http.StatusFound {
			t.Fatalf("want a redirect back, got %d %s", w.Code, w.Body)
		}
		back, _ := url.Parse(w.Header().Get("Location"))
		if back.Query().Get("grant") != "" || back.Query().Get("nonce") != "abcdefgh12345678" {
			t.Fatalf("a failure carries no grant and keeps the nonce: %s", back)
		}
		return back.Query().Get("error")
	}

	if got := errorOf(get(m, CallbackPath+"?error=access_denied&error_description=Some+long+text&state="+start())); got != "access_denied" {
		t.Errorf("provider refusal: %q", got)
	}
	if got := errorOf(get(m, CallbackPath+"?error=%3Cscript%3E&state="+start())); got != "denied" {
		t.Errorf("an odd error code is not relayed: %q", got)
	}
	if got := errorOf(get(m, CallbackPath+"?code=wrong&state="+start())); got != "exchange_failed" {
		t.Errorf("exchange failure: %q", got)
	}
	f.Identify = func(context.Context, Tokens) (string, error) { return "", errors.New("no") }
	st := start()
	if got := errorOf(get(m, CallbackPath+"?code="+p.code+"&state="+st)); got != "probe_failed" {
		t.Errorf("probe failure: %q", got)
	}
	if w := get(m, CallbackPath+"?code=x&state=never-started"); w.Code != http.StatusBadRequest {
		t.Errorf("unknown state: %d", w.Code)
	}
}

// A sign-in and a grant code both age out after ten minutes.
func TestStateAndGrantExpire(t *testing.T) {
	p := newFakeProvider(t)
	f, m := newFlow(t, p)
	now := time.Now()
	f.now = func() time.Time { return now }

	w := get(m, startOK)
	loc, _ := url.Parse(w.Header().Get("Location"))
	_, _ = http.Get(loc.String())
	now = now.Add(ttl + time.Second)
	if w := get(m, CallbackPath+"?code="+p.code+"&state="+loc.Query().Get("state")); w.Code != http.StatusBadRequest {
		t.Fatalf("an expired sign-in should be refused: %d", w.Code)
	}

	w = get(m, startOK)
	loc, _ = url.Parse(w.Header().Get("Location"))
	_, _ = http.Get(loc.String())
	w = get(m, CallbackPath+"?code="+p.code+"&state="+loc.Query().Get("state"))
	back, _ := url.Parse(w.Header().Get("Location"))
	grant := back.Query().Get("grant")
	now = now.Add(ttl + time.Second)
	if _, ok := f.Redeem(grant); ok {
		t.Fatal("an expired grant code was redeemed")
	}
}

func TestRefresh(t *testing.T) {
	p := newFakeProvider(t)
	f, _ := newFlow(t, p)
	got, err := f.Refresh(context.Background(), "rt-1")
	if err != nil || got.AccessToken != "at-2" || got.RefreshToken != "rt-1" || got.Expiry.IsZero() {
		t.Fatalf("refresh: %+v %v", got, err)
	}
	if _, err := f.Refresh(context.Background(), "rt-revoked"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a refused refresh token is ErrRefused: %v", err)
	}
	if _, err := f.Refresh(context.Background(), ""); err == nil {
		t.Fatal("an empty refresh token is an error before any call")
	}
}

func TestSchemaProperty(t *testing.T) {
	p := newFakeProvider(t)
	f, _ := newFlow(t, p)
	r := httptest.NewRequest(http.MethodGet, "/v1/capabilities/setup", nil)
	r.Host = "cal.apps.example"
	prop := f.SchemaProperty(r)
	x, _ := prop["x-privasys-oauth"].(map[string]string)
	if prop["type"] != "string" || x["provider"] != "Example" || x["start_url"] != "https://cal.apps.example/v1/oauth/start?kind=calendar.events" {
		t.Fatalf("schema property: %+v", prop)
	}
	r.Header.Set("X-Forwarded-Host", "public.example")
	if x, _ := f.SchemaProperty(r)["x-privasys-oauth"].(map[string]string); !strings.HasPrefix(x["start_url"], "https://public.example/") {
		t.Fatalf("the forwarded host is the public one: %+v", x)
	}
}
