// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
	"github.com/Privasys/connectors/calendar/internal/caldavdrv"
	"github.com/Privasys/connectors/calendar/internal/config"
	"github.com/Privasys/connectors/calendar/internal/graphdrv"
	"github.com/Privasys/connectors/calendar/internal/store"
	"github.com/Privasys/connectors/sdk/oauth"
)

// fakeMicrosoft is the identity platform's authorisation and token
// endpoints: it issues a code for any sign-in, exchanges it for tokens
// once, and refreshes rt-1 only when the scope is named again, which is
// what the real endpoint wants.
type fakeMicrosoft struct {
	srv       *httptest.Server
	code      string
	scopeSeen string
	refreshes int
}

func newFakeMicrosoft(t *testing.T) *fakeMicrosoft {
	t.Helper()
	m := &fakeMicrosoft{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		m.scopeSeen = q.Get("scope")
		m.code = "code-" + q.Get("state")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+m.code+"&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("client_id") != "mcid" || r.Form.Get("client_secret") != "msecret" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != m.code {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			m.code = ""
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "ms-at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600})
		case "refresh_token":
			m.refreshes++
			if !strings.Contains(r.Form.Get("scope"), "Calendars.ReadWrite") {
				http.Error(w, `{"error":"invalid_request","error_description":"scope is required"}`, http.StatusBadRequest)
				return
			}
			if r.Form.Get("refresh_token") != "rt-1" {
				http.Error(w, `{"error":"invalid_grant","error_description":"The refresh token has expired or been revoked."}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "ms-at-2", "refresh_token": "rt-2", "token_type": "Bearer", "expires_in": 3600})
		}
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

// fakeGraphDriver is the Graph seam's answer: a calendar like the CalDAV
// fake's, and the address Graph says signed in.
type fakeGraphDriver struct {
	fakeDriver
	user string
}

func (f *fakeGraphDriver) User() string { return f.user }

// microsoftRig points the Microsoft flow and the token endpoint at the
// fake, and opens Graph accounts onto fake drivers that sign in as
// identity.
func microsoftRig(t *testing.T, m *fakeMicrosoft, identity string) *rig {
	t.Helper()
	r := newRig(t, true)
	p := microsoft
	p.AuthURL, p.TokenURL = m.srv.URL+"/auth", m.srv.URL+"/token"
	r.s.flows = oauth.NewMulti(cal.Kind)
	r.s.flows.Add(store.ProviderGoogle, google)
	f := r.s.flows.Add(store.ProviderMicrosoft, p)
	f.Identify = r.s.identifyMicrosoft
	f.HTTPClient = m.srv.Client()
	r.s.microsoftTokenURL = m.srv.URL + "/token"
	r.s.http = m.srv.Client()
	r.s.applyConfig(config.Config{MicrosoftClientID: "mcid", MicrosoftClientSecret: "msecret"})
	r.s.openGraph = func(ctx context.Context, cfg graphdrv.Config) (graphDriver, error) {
		tok, err := cfg.Token(ctx)
		if err != nil {
			return nil, err
		}
		r.bearers = append(r.bearers, tok)
		if tok == "bad-token" {
			return nil, graphdrv.ErrLogin
		}
		d := &fakeGraphDriver{fakeDriver: *newFakeDriver(caldavdrv.Config{}), user: identity}
		return d, nil
	}
	return r
}

func signInMicrosoft(t *testing.T, r *rig, m *fakeMicrosoft) string {
	t.Helper()
	w := r.do(http.MethodGet, "/v1/oauth/start?kind=calendar.events&provider=microsoft&redirect_uri=privasys-wallet%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh12345678", nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	res, err := m.srv.Client().Transport.RoundTrip(mustGet(w.Header().Get("Location")))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	cb, _ := url.Parse(res.Header.Get("Location"))
	w = r.do(http.MethodGet, cb.RequestURI(), nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	back, _ := url.Parse(w.Header().Get("Location"))
	if back.Query().Get("grant") == "" {
		t.Fatalf("the wallet gets the grant: %s", back)
	}
	return back.Query().Get("grant")
}

// The whole Microsoft path: a Microsoft address, the button, the sign-in,
// the mint with the grant, the credential proved through Graph and kept,
// the wallet keeping the refresh token and the provider; a tool call on
// the Graph driver that refreshes with the scope named; then a restart
// where the wallet sends what it kept, with no browser and no resolver.
func TestMicrosoftSignInMintAndKeptToken(t *testing.T) {
	m := newFakeMicrosoft(t)
	r := microsoftRig(t, m, "me@tenant.example")
	grant := signInMicrosoft(t, r, m)
	if !strings.Contains(m.scopeSeen, "offline_access") || !strings.Contains(m.scopeSeen, "Calendars.ReadWrite") {
		t.Fatalf("the scopes asked of Microsoft: %q", m.scopeSeen)
	}
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("m"), mintBody(map[string]any{"user": "Me@tenant.example", "grant": grant}))
	if w.Code != http.StatusOK {
		t.Fatalf("mint with the grant: %d %s", w.Code, w.Body)
	}
	var got struct {
		Keep map[string]string `json:"keep"`
	}
	decode(t, w, &got)
	if got.Keep["refresh_token"] != "rt-1" || got.Keep["provider"] != "microsoft" {
		t.Fatalf("the wallet keeps the refresh token and the provider: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "ms-at-1") {
		t.Fatal("the access token was handed out")
	}
	acct, err := r.s.credStore().Get(context.Background(), "m")
	if err != nil || acct.Provider != store.ProviderMicrosoft || acct.RefreshToken != "rt-1" || acct.Endpoint != "" {
		t.Fatalf("kept: %+v %v", acct, err)
	}
	if w := r.call(t, "m", "list_calendars", `{}`); w.Code != http.StatusOK {
		t.Fatalf("a Microsoft account serves through Graph: %d %s", w.Code, w.Body)
	}
	acct.Expiry = time.Now().Add(-time.Minute)
	_ = r.s.credStore().Put(context.Background(), "m", acct)
	r.s.dropConn("m")
	if w := r.call(t, "m", "list_calendars", `{}`); w.Code != http.StatusOK {
		t.Fatalf("after an expiry: %d %s", w.Code, w.Body)
	}
	if m.refreshes != 1 || r.bearers[len(r.bearers)-1] != "ms-at-2" {
		t.Fatalf("refreshed once, with the scope: refreshes=%d bearers=%v", m.refreshes, r.bearers)
	}
	if acct, _ := r.s.credStore().Get(context.Background(), "m"); acct.RefreshToken != "rt-2" {
		t.Fatalf("the rotated refresh token goes back into memory: %+v", acct)
	}

	// A restart: the wallet sends what it kept. The provider it kept wins
	// over the resolver, which is offline here.
	r2 := microsoftRig(t, m, "me@tenant.example")
	r2.s.who = nil
	w = r2.do(http.MethodPost, "/v1/capabilities", asHolder("m"), mintBody(map[string]any{"user": "me@tenant.example", "kept": map[string]any{"refresh_token": "rt-1", "provider": "microsoft"}}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"refresh_token":"rt-2"`) {
		t.Fatalf("mint with the kept token: %d %s", w.Code, w.Body)
	}
	// A kept token the provider refuses is a 502 with a sentence.
	w = r2.do(http.MethodPost, "/v1/capabilities", asHolder("m3"), mintBody(map[string]any{"user": "me@tenant.example", "kept": map[string]any{"refresh_token": "rt-revoked", "provider": "microsoft"}}))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "no longer accepts") {
		t.Fatalf("a refused kept token: %d %s", w.Code, w.Body)
	}
}

// The sign-in must be for the address the holder typed, on the grant path
// and on the kept path alike.
func TestMicrosoftSignInForAnotherAccountIsRefused(t *testing.T) {
	m := newFakeMicrosoft(t)
	r := microsoftRig(t, m, "other@tenant.example")
	grant := signInMicrosoft(t, r, m)
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("m"), mintBody(map[string]any{"user": "me@tenant.example", "grant": grant}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "other@tenant.example") {
		t.Fatalf("a sign-in for another account: %d %s", w.Code, w.Body)
	}
	if _, err := r.s.credStore().Get(context.Background(), "m"); err == nil {
		t.Fatal("nothing may be kept for a mismatched sign-in")
	}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("m"), mintBody(map[string]any{"user": "me@tenant.example", "kept": map[string]any{"refresh_token": "rt-1", "provider": "microsoft"}}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "other@tenant.example") {
		t.Fatalf("a kept token for another account: %d %s", w.Code, w.Body)
	}
}
