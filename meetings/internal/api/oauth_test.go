// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Privasys/connectors/meetings/internal/meet"
	"github.com/Privasys/connectors/meetings/internal/store"
)

// fakeAuth is an authorisation server and token endpoint: it issues a code
// for any sign-in, exchanges it for tokens once, refreshes rt-1 and refuses
// every other refresh token. basic says whether it wants the client
// credentials as HTTP Basic (Zoom) or in the body (Microsoft).
type fakeAuth struct {
	srv     *httptest.Server
	basic   bool
	code    string
	scope   string
	refresh int
	// rotate hands out a new refresh token at every refresh, as Zoom does.
	rotate bool
}

func newFakeAuth(t *testing.T, basic, rotate bool) *fakeAuth {
	t.Helper()
	g := &fakeAuth{basic: basic, rotate: rotate}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		g.scope = q.Get("scope")
		g.code = "code-" + q.Get("state")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+g.code+"&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		id, secret, ok := r.BasicAuth()
		if g.basic {
			if !ok || id != "cid" || secret != "csecret" {
				http.Error(w, `{"error":"invalid_client","reason":"Basic wanted"}`, http.StatusUnauthorized)
				return
			}
		} else if ok || r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "csecret" {
			http.Error(w, `{"error":"invalid_client","reason":"body wanted"}`, http.StatusUnauthorized)
			return
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != g.code {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			g.code = ""
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600})
		case "refresh_token":
			g.refresh++
			if r.Form.Get("refresh_token") != "rt-1" && !(g.rotate && strings.HasPrefix(r.Form.Get("refresh_token"), "rt-")) {
				http.Error(w, `{"error":"invalid_grant","error_description":"Invalid refresh token."}`, http.StatusBadRequest)
				return
			}
			out := map[string]any{"access_token": "at-2", "token_type": "Bearer", "expires_in": 3600}
			if g.rotate {
				out["refresh_token"] = "rt-2"
			}
			_ = json.NewEncoder(w).Encode(out)
		}
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

// oauthRig points both providers at fakes.
func oauthRig(t *testing.T, zoom, ms *fakeAuth) *rig {
	t.Helper()
	r := newRig(t)
	z := zoomProvider("user:read:user cloud_recording:read:list_user_recordings")
	z.AuthURL, z.TokenURL = zoom.srv.URL+"/auth", zoom.srv.URL+"/token"
	m := microsoft
	m.AuthURL, m.TokenURL = ms.srv.URL+"/auth", ms.srv.URL+"/token"
	r.s.installFlow(meet.ProviderZoom, z, "cid", "csecret")
	r.s.installFlow(meet.ProviderTeams, m, "cid", "csecret")
	return r
}

// signIn plays the wallet and the browser: start, the provider, the
// callback, and returns the grant code the wallet was sent back with.
func signIn(t *testing.T, r *rig, g *fakeAuth, slug string) string {
	t.Helper()
	w := r.do(http.MethodGet, "/v1/oauth/start?kind=meeting.transcripts&provider="+slug+"&redirect_uri=privasys-wallet%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh12345678", nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	req, _ := http.NewRequest(http.MethodGet, w.Header().Get("Location"), nil)
	res, err := g.srv.Client().Transport.RoundTrip(req)
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

// The whole path at each provider: the address, sign in, mint with the
// grant, the credential is proved and kept, the wallet keeps the refresh
// token and the provider; then a restart, the wallet sends the token back,
// and the account is connected without a browser and without the
// resolver.
func TestSignInMintAndKeptTokenAtBothProviders(t *testing.T) {
	for _, c := range []struct {
		slug, choice, user string
		basic              bool
	}{
		{meet.ProviderZoom, "Zoom", "me@example.org", true},
		{meet.ProviderTeams, "Microsoft Teams", "me@tenant.example", false},
	} {
		t.Run(c.slug, func(t *testing.T) {
			zoom, ms := newFakeAuth(t, true, true), newFakeAuth(t, false, false)
			r := oauthRig(t, zoom, ms)
			r.identity = c.user
			g := ms
			if c.slug == meet.ProviderZoom {
				g = zoom
			}
			code := signIn(t, r, g, c.slug)
			if c.slug == meet.ProviderZoom && !strings.Contains(g.scope, "cloud_recording:read:list_user_recordings") {
				t.Errorf("zoom scopes from the configuration: %q", g.scope)
			}
			if c.slug == meet.ProviderTeams && !strings.Contains(g.scope, "OnlineMeetingTranscript.Read.All") {
				t.Errorf("microsoft scopes: %q", g.scope)
			}

			w := r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), mintBody(map[string]any{"user": strings.ToUpper(c.user), "provider": c.choice, "grant": code}))
			if w.Code != http.StatusOK {
				t.Fatalf("mint: %d %s", w.Code, w.Body)
			}
			var out struct {
				Keep          map[string]string `json:"keep"`
				ServiceResult map[string]string `json:"service_result"`
			}
			decode(t, w, &out)
			if out.Keep["refresh_token"] != "rt-1" || out.Keep["provider"] != c.slug || out.ServiceResult["account"] != c.user {
				t.Fatalf("mint answer: %s", w.Body)
			}
			// The credential is in memory and the tools work.
			if w := r.call(t, "u1", "list_meetings", `{}`); w.Code != http.StatusOK {
				t.Fatalf("list: %d %s", w.Code, w.Body)
			}
			// A second redeem of the same code is refused.
			if w := r.do(http.MethodPost, "/v1/capabilities", asHolder("u2"), mintBody(map[string]any{"user": c.user, "provider": c.choice, "grant": code})); w.Code != http.StatusPreconditionRequired {
				t.Errorf("a used code: %d %s", w.Code, w.Body)
			}

			// A restart: everything forgotten. The wallet sends the kept
			// token and the provider; the resolver is not asked.
			r.s.svc.ForgetEveryone()
			r.s.who = nil
			if w := r.call(t, "u1", "list_meetings", `{}`); w.Code != http.StatusForbidden {
				t.Fatalf("after the restart: %d", w.Code)
			}
			w = r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), mintBody(map[string]any{"user": c.user, "kept": map[string]any{"refresh_token": "rt-1", "provider": c.slug}}))
			if w.Code != http.StatusOK {
				t.Fatalf("mint with the kept token: %d %s", w.Code, w.Body)
			}
			decode(t, w, &out)
			wantKept := "rt-1"
			if g.rotate {
				// Zoom rotated it; the wallet is handed the current one.
				wantKept = "rt-2"
			}
			if out.Keep["refresh_token"] != wantKept || g.refresh != 1 {
				t.Errorf("kept token after the restart: %v (refreshes %d)", out.Keep, g.refresh)
			}
			if w := r.call(t, "u1", "account", `{}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"provider":"`+c.slug+`"`) {
				t.Errorf("account: %d %s", w.Code, w.Body)
			}

			// A kept token the provider refuses: sign in again, said plainly.
			r.s.svc.ForgetEveryone()
			w = r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), mintBody(map[string]any{"user": c.user, "kept": map[string]any{"refresh_token": "revoked", "provider": c.slug}}))
			if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "sign in again") {
				t.Errorf("refused kept token: %d %s", w.Code, w.Body)
			}
		})
	}
}

// The sign-in must be for the address the holder typed, at Zoom (its
// /users/me email) and at Microsoft (Graph's /me) alike, on the grant path
// and on the kept path.
func TestSignInForAnotherAddressIsRefused(t *testing.T) {
	for _, c := range []struct{ slug, choice, user string }{
		{meet.ProviderZoom, "Zoom", "me@example.org"},
		{meet.ProviderTeams, "Microsoft Teams", "me@tenant.example"},
	} {
		t.Run(c.slug, func(t *testing.T) {
			zoom, ms := newFakeAuth(t, true, true), newFakeAuth(t, false, false)
			r := oauthRig(t, zoom, ms)
			r.identity = "other@" + strings.SplitN(c.user, "@", 2)[1]
			g := ms
			if c.slug == meet.ProviderZoom {
				g = zoom
			}
			code := signIn(t, r, g, c.slug)
			w := r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), mintBody(map[string]any{"user": c.user, "provider": c.choice, "grant": code}))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), r.identity) {
				t.Fatalf("a sign-in for another account: %d %s", w.Code, w.Body)
			}
			if _, err := r.s.credStore().Get(t.Context(), "u1"); err == nil {
				t.Fatal("nothing may be kept for a mismatched sign-in")
			}
			w = r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), mintBody(map[string]any{"user": c.user, "kept": map[string]any{"refresh_token": "rt-1", "provider": c.slug}}))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), r.identity) {
				t.Fatalf("a kept token for another account: %d %s", w.Code, w.Body)
			}
		})
	}
}

// A tool call whose access token has expired refreshes it from the kept
// token without the holder noticing.
func TestExpiredAccessTokenIsRefreshed(t *testing.T) {
	zoom, ms := newFakeAuth(t, true, true), newFakeAuth(t, false, false)
	r := oauthRig(t, zoom, ms)
	_ = r.s.credStore().Put(t.Context(), "u1", store.Account{Provider: meet.ProviderZoom, User: "me@example.org", RefreshToken: "rt-1", AccessToken: "at-old"})
	r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), mintBody(nil))
	if w := r.call(t, "u1", "list_meetings", `{}`); w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if zoom.refresh != 1 || r.drivers[len(r.drivers)-1].tokens[0] != "at-2" {
		t.Errorf("the driver was opened with the refreshed token: refreshes=%d tokens=%v", zoom.refresh, r.drivers[len(r.drivers)-1].tokens)
	}
	acct, _ := r.s.credStore().Get(t.Context(), "u1")
	if acct.RefreshToken != "rt-2" || acct.AccessToken != "at-2" {
		t.Errorf("the rotated tokens are kept in memory: %+v", acct.Redacted())
	}
}
