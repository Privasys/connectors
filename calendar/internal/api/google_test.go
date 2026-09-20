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

	"github.com/Privasys/connectors/calendar/internal/store"
	"github.com/Privasys/connectors/sdk/oauth"
)

// fakeGoogle is the authorisation server, the token endpoint and userinfo
// in one: it issues a code for any sign-in, exchanges it for tokens once,
// refreshes rt-1 and refuses every other refresh token.
type fakeGoogle struct {
	srv      *httptest.Server
	code     string
	redirect string
	email    string
	refresh  int
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	t.Helper()
	g := &fakeGoogle{email: "me@gmail.com"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("access_type") != "offline" || q.Get("prompt") != "consent" || !strings.Contains(q.Get("scope"), "auth/calendar") {
			http.Error(w, "the request would not yield a refresh token", http.StatusBadRequest)
			return
		}
		g.code = "code-" + q.Get("state")
		g.redirect = q.Get("redirect_uri")
		// The browser is sent back to the connector's callback.
		http.Redirect(w, r, g.redirect+"?code="+g.code+"&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != g.code || r.Form.Get("client_secret") != "csecret" {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			g.code = ""
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600})
		case "refresh_token":
			g.refresh++
			if r.Form.Get("refresh_token") != "rt-1" {
				http.Error(w, `{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-2", "token_type": "Bearer", "expires_in": 3600})
		}
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-1" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"email": g.email})
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

// googleRig points the connector's provider at the fake.
func googleRig(t *testing.T, g *fakeGoogle) *rig {
	t.Helper()
	r := newRig(t, true)
	p := google
	p.AuthURL, p.TokenURL = g.srv.URL+"/auth", g.srv.URL+"/token"
	r.s.flow = oauth.New(p, "calendar.events")
	r.s.flow.Identify = r.s.identify
	r.s.flow.HTTPClient = g.srv.Client()
	r.s.flow.SetClient("cid", "csecret")
	r.s.userinfo = g.srv.URL + "/userinfo"
	r.s.http = g.srv.Client()
	return r
}

// signIn plays the wallet and the browser: start, the provider, the
// callback, and returns the grant code the wallet was sent back with.
func signIn(t *testing.T, r *rig, g *fakeGoogle) string {
	t.Helper()
	w := r.do(http.MethodGet, "/v1/oauth/start?kind=calendar.events&redirect_uri=privasys-wallet%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh12345678", nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	// The provider answers the browser with a redirect to the callback.
	res, err := g.srv.Client().Transport.RoundTrip(mustGet(w.Header().Get("Location")))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	cb, _ := url.Parse(res.Header.Get("Location"))
	if cb == nil || cb.Path != "/v1/oauth/callback" {
		t.Fatalf("the provider should send the browser to the callback: %v", res.Header.Get("Location"))
	}
	w = r.do(http.MethodGet, cb.RequestURI(), nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	back, _ := url.Parse(w.Header().Get("Location"))
	if back.Scheme != "privasys-wallet" || back.Query().Get("grant") == "" {
		t.Fatalf("the wallet gets the grant: %s", back)
	}
	return back.Query().Get("grant")
}

func mustGet(u string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	return req
}

// The whole Google path: sign in, mint with the grant, the credential is
// proved and kept, the wallet keeps the refresh token; then a restart, the
// wallet sends the token back, and the account is connected without a
// browser.
func TestGoogleSignInMintAndKeptToken(t *testing.T) {
	g := newFakeGoogle(t)
	r := googleRig(t, g)
	grant := signIn(t, r, g)

	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("g"), mintBody(map[string]any{"user": "me@gmail.com", "grant": grant}))
	if w.Code != http.StatusOK {
		t.Fatalf("mint with the grant: %d %s", w.Code, w.Body)
	}
	var got struct {
		Keep map[string]string `json:"keep"`
	}
	decode(t, w, &got)
	if got.Keep["refresh_token"] != "rt-1" {
		t.Fatalf("the wallet keeps the refresh token: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "at-1") {
		t.Fatal("the access token was handed out")
	}
	acct, err := r.s.credStore().Get(context.Background(), "g")
	if err != nil || acct.Provider != store.ProviderGoogle || acct.RefreshToken != "rt-1" || acct.AccessToken != "at-1" || acct.Principal != "/caldav/v2/me@gmail.com/user" {
		t.Fatalf("kept: %+v %v", acct, err)
	}
	if len(r.bearers) == 0 || r.bearers[0] != "at-1" {
		t.Fatalf("the probe used the access token: %v", r.bearers)
	}
	// The grant is single use.
	if w := r.do(http.MethodPost, "/v1/capabilities", asHolder("g2"), mintBody(map[string]any{"user": "me@gmail.com", "grant": grant})); w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), "already used") {
		t.Fatalf("a used grant is one more sign-in: %d %s", w.Code, w.Body)
	}
	// A tool call runs with the bearer, and refreshes it when it has expired.
	if w := r.do(http.MethodPost, "/tools/list_calendars", asUser("g"), `{}`); w.Code != http.StatusOK {
		t.Fatalf("a Google account serves: %d %s", w.Code, w.Body)
	}
	acct.Expiry = time.Now().Add(-time.Minute)
	_ = r.s.credStore().Put(context.Background(), "g", acct)
	r.s.dropConn("g")
	if w := r.do(http.MethodPost, "/tools/list_calendars", asUser("g"), `{}`); w.Code != http.StatusOK {
		t.Fatalf("after an expiry: %d %s", w.Code, w.Body)
	}
	if g.refresh != 1 || r.bearers[len(r.bearers)-1] != "at-2" {
		t.Fatalf("the expired token should have been refreshed once: refreshes=%d bearers=%v", g.refresh, r.bearers)
	}
	if acct, _ := r.s.credStore().Get(context.Background(), "g"); acct.AccessToken != "at-2" || acct.RefreshToken != "rt-1" {
		t.Fatalf("the refreshed token goes back into memory: %+v", acct)
	}

	// A restart: the wallet sends what it kept, no browser.
	r2 := googleRig(t, g)
	w = r2.do(http.MethodPost, "/v1/capabilities", asHolder("g"), mintBody(map[string]any{"user": "me@gmail.com", "kept": map[string]any{"refresh_token": "rt-1"}}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"refresh_token":"rt-1"`) {
		t.Fatalf("mint with the kept token: %d %s", w.Code, w.Body)
	}
	if acct, err := r2.s.credStore().Get(context.Background(), "g"); err != nil || acct.AccessToken != "at-2" {
		t.Fatalf("connected from the kept token: %+v %v", acct, err)
	}
	// A kept token the provider refuses is a 502 with a sentence.
	w = r2.do(http.MethodPost, "/v1/capabilities", asHolder("g3"), mintBody(map[string]any{"user": "me@gmail.com", "kept": map[string]any{"refresh_token": "rt-revoked"}}))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "no longer accepts") {
		t.Fatalf("a refused kept token: %d %s", w.Code, w.Body)
	}
}

// The sign-in must be for the address the holder typed.
func TestGoogleSignInForAnotherAccountIsRefused(t *testing.T) {
	g := newFakeGoogle(t)
	g.email = "other@gmail.com"
	r := googleRig(t, g)
	grant := signIn(t, r, g)
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("g"), mintBody(map[string]any{"user": "me@gmail.com", "grant": grant}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "other@gmail.com") {
		t.Fatalf("a sign-in for another account: %d %s", w.Code, w.Body)
	}
	if _, err := r.s.credStore().Get(context.Background(), "g"); err == nil {
		t.Fatal("nothing may be kept for a mismatched sign-in")
	}
}
