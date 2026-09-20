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

	"github.com/Privasys/connectors/files/internal/cloud"
	"github.com/Privasys/connectors/files/internal/config"
	"github.com/Privasys/connectors/sdk/oauth"
	"github.com/Privasys/connectors/sdk/provider"
)

// fakeIdP is an authorisation server and token endpoint for one provider:
// it issues a code for any sign-in, exchanges it for tokens once, refreshes
// rt-1 and refuses every other refresh token. For Microsoft it also insists
// the scope is named again on a refresh, which is what that endpoint wants.
type fakeIdP struct {
	srv       *httptest.Server
	name      string
	code      string
	scopeSeen string
	refreshes int
	wantScope bool
}

func newFakeIdP(t *testing.T, name string, wantScope bool) *fakeIdP {
	t.Helper()
	p := &fakeIdP{name: name, wantScope: wantScope}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p.scopeSeen = q.Get("scope")
		p.code = "code-" + q.Get("state")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+p.code+"&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("client_id") != name+"-cid" || r.Form.Get("client_secret") != name+"-secret" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != p.code {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			p.code = ""
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": name + "-at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600})
		case "refresh_token":
			p.refreshes++
			if p.wantScope && !strings.Contains(r.Form.Get("scope"), "Files.Read.All") {
				http.Error(w, `{"error":"invalid_request","error_description":"scope is required"}`, http.StatusBadRequest)
				return
			}
			if r.Form.Get("refresh_token") != "rt-1" {
				http.Error(w, `{"error":"invalid_grant","error_description":"The refresh token has expired or been revoked."}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": name + "-at-2", "refresh_token": "rt-2", "token_type": "Bearer", "expires_in": 3600})
		}
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// oauthRig points both providers at fakes and configures both clients.
func oauthRig(t *testing.T, ms, gg *fakeIdP) *rig {
	t.Helper()
	r := newRig(t, true)
	r.s.flows = oauth.NewMulti(cloud.Kind)
	pm := microsoft
	pm.AuthURL, pm.TokenURL = ms.srv.URL+"/auth", ms.srv.URL+"/token"
	fm := r.s.flows.Add(cloud.ProviderMicrosoft, pm)
	fm.Identify = r.s.identifier(cloud.ProviderMicrosoft)
	fm.HTTPClient = ms.srv.Client()
	pg := google
	pg.AuthURL, pg.TokenURL = gg.srv.URL+"/auth", gg.srv.URL+"/token"
	fg := r.s.flows.Add(cloud.ProviderGoogle, pg)
	fg.Identify = r.s.identifier(cloud.ProviderGoogle)
	fg.HTTPClient = gg.srv.Client()
	r.s.microsoftTokenURL = ms.srv.URL + "/token"
	r.s.http = ms.srv.Client()
	r.s.applyConfig(clients(true, true))
	return r
}

// signIn plays the wallet and the browser for one provider: start, the
// provider, the callback, and returns the grant code the wallet was sent
// back with.
func signIn(t *testing.T, r *rig, p *fakeIdP, provider string) string {
	t.Helper()
	w := r.do(http.MethodGet, "/v1/oauth/start?kind=files.cloud&provider="+provider+"&redirect_uri=privasys-wallet%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh12345678", nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("start %s: %d %s", provider, w.Code, w.Body)
	}
	res, err := p.srv.Client().Transport.RoundTrip(mustGet(w.Header().Get("Location")))
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

// The two-step setup: the address first, then the button for the provider
// the address names. A holder is never asked to pick a provider, and an
// address at a provider this connector cannot reach, or one whose client
// is not configured here, gets a sentence and nothing to fill.
func TestSetupAsksTheAddressThenDrawsTheButtonForItsProvider(t *testing.T) {
	r := oauthRig(t, newFakeIdP(t, "microsoft", true), newFakeIdP(t, "google", false))
	w := r.do(http.MethodGet, "/v1/capabilities/setup", asHolder("h1"), "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"user":{`) || strings.Contains(w.Body.String(), `"provider":{`) || strings.Contains(w.Body.String(), "x-privasys-oauth") {
		t.Fatalf("first step is the address alone: %d %s", w.Code, w.Body)
	}
	type elicit struct {
		Elicit struct {
			Message string `json:"message"`
			Schema  struct {
				Properties map[string]map[string]any `json:"properties"`
			} `json:"requestedSchema"`
		} `json:"elicit"`
	}
	ask := func(user string) (int, elicit, string) {
		w := r.do(http.MethodPost, "/v1/capabilities", asHolder("h1"), mintBody(map[string]any{"user": user}))
		var got elicit
		if w.Code == http.StatusPreconditionRequired {
			decode(t, w, &got)
		}
		return w.Code, got, w.Body.String()
	}
	// The providers' own domains, and custom domains through their MX.
	for user, want := range map[string]string{
		"me@gmail.com":         "google",
		"me@workspace.example": "google",
		"me@outlook.com":       "microsoft",
		"me@example.org":       "microsoft",
	} {
		code, got, body := ask(user)
		if code != http.StatusPreconditionRequired {
			t.Fatalf("%s: %d %s", user, code, body)
		}
		x, _ := got.Elicit.Schema.Properties["grant"]["x-privasys-oauth"].(map[string]any)
		if x["provider"] != provider.Provider(want).Name() || x["start_url"] != "https://files.apps.example/v1/oauth/start?kind=files.cloud&provider="+want {
			t.Fatalf("%s: the button: %+v", user, got.Elicit.Schema.Properties)
		}
		if _, ok := got.Elicit.Schema.Properties["provider"]; ok {
			t.Fatalf("%s: the holder is never asked to pick a provider the domain names", user)
		}
		if got.Elicit.Schema.Properties["user"]["default"] != user {
			t.Fatalf("%s: the address is carried forward: %+v", user, got.Elicit.Schema.Properties["user"])
		}
	}
	// Hosted elsewhere, or nowhere the resolver knows: not reachable, said
	// plainly, naming the two, with nothing to fill.
	for _, user := range []string{"me@self.example", "me@icloud.com", "me@nowhere.example"} {
		code, got, body := ask(user)
		if code != http.StatusPreconditionRequired || len(got.Elicit.Schema.Properties) != 0 ||
			!strings.Contains(got.Elicit.Message, "Microsoft") || !strings.Contains(got.Elicit.Message, "Google") || !strings.Contains(got.Elicit.Message, "not at a provider this connector can reach") {
			t.Fatalf("%s: %d %s", user, code, body)
		}
	}
	// Not an address at all: asked again.
	if code, _, body := ask("not-an-address"); code != http.StatusPreconditionRequired || !strings.Contains(body, `"user":{`) || strings.Contains(body, "x-privasys-oauth") {
		t.Fatalf("no domain: %d %s", code, body)
	}
	// A provider without a client configured says so, with nothing to fill.
	r.s.applyConfig(clients(false, true))
	code, got, body := ask("me@outlook.com")
	if code != http.StatusPreconditionRequired || len(got.Elicit.Schema.Properties) != 0 || !strings.Contains(got.Elicit.Message, "no Microsoft sign-in configured") {
		t.Fatalf("unconfigured provider: %d %s", code, body)
	}
	if code, got, body := ask("me@gmail.com"); code != http.StatusPreconditionRequired || got.Elicit.Schema.Properties["grant"] == nil {
		t.Fatalf("the other provider still signs in: %d %s", code, body)
	}
}

// The whole Microsoft path: a Microsoft address, sign in, mint with the
// grant, the credential is proved and kept, the wallet keeps the refresh
// token and the provider; a tool call runs with the bearer and refreshes
// it with the scope named; then a restart, the wallet sends the token
// back, and the account is connected without a browser.
func TestMicrosoftSignInMintAndKeptToken(t *testing.T) {
	ms, gg := newFakeIdP(t, "microsoft", true), newFakeIdP(t, "google", false)
	r := oauthRig(t, ms, gg)
	grant := signIn(t, r, ms, "microsoft")
	if !strings.Contains(ms.scopeSeen, "offline_access") || !strings.Contains(ms.scopeSeen, "Files.ReadWrite") {
		t.Fatalf("the scopes asked of Microsoft: %q", ms.scopeSeen)
	}

	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("m"), mintBody(map[string]any{"user": "Me@example.org", "grant": grant}))
	if w.Code != http.StatusOK {
		t.Fatalf("mint with the grant: %d %s", w.Code, w.Body)
	}
	var got struct {
		Keep          map[string]string `json:"keep"`
		ServiceResult map[string]string `json:"service_result"`
	}
	decode(t, w, &got)
	if got.Keep["refresh_token"] != "rt-1" || got.Keep["provider"] != "microsoft" || got.ServiceResult["account"] != "me@example.org" {
		t.Fatalf("the wallet keeps the refresh token and the provider, and learns the account: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "at-1") {
		t.Fatal("the access token was handed out")
	}
	acct, err := r.s.credStore().Get(context.Background(), "m")
	if err != nil || acct.Provider != cloud.ProviderMicrosoft || acct.RefreshToken != "rt-1" || acct.AccessToken != "microsoft-at-1" || acct.DriveID != "d1" {
		t.Fatalf("kept: %+v %v", acct, err)
	}
	// The grant is single use.
	if w := r.do(http.MethodPost, "/v1/capabilities", asHolder("m2"), mintBody(map[string]any{"user": "me@example.org", "grant": grant})); w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), "already used") {
		t.Fatalf("a used grant is one more sign-in: %d %s", w.Code, w.Body)
	}
	// A tool call runs with the bearer, and refreshes it when it has
	// expired, naming the scope, and the rotated refresh token is kept.
	if w := r.call(t, "m", "list_drives", `{}`); w.Code != http.StatusOK {
		t.Fatalf("serves: %d %s", w.Code, w.Body)
	}
	acct.Expiry = time.Now().Add(-time.Minute)
	_ = r.s.credStore().Put(context.Background(), "m", acct)
	r.s.dropConn("m")
	if w := r.call(t, "m", "list_drives", `{}`); w.Code != http.StatusOK {
		t.Fatalf("after an expiry: %d %s", w.Code, w.Body)
	}
	if ms.refreshes != 1 || r.bearers[len(r.bearers)-1] != "microsoft-at-2" {
		t.Fatalf("refreshed once with the scope: refreshes=%d bearers=%v", ms.refreshes, r.bearers)
	}
	if acct, _ := r.s.credStore().Get(context.Background(), "m"); acct.AccessToken != "microsoft-at-2" || acct.RefreshToken != "rt-2" {
		t.Fatalf("the refreshed tokens go back into memory: %+v", acct)
	}

	// A restart: the wallet sends what it kept, no browser. The provider it
	// kept wins over the resolver, which is offline here.
	r2 := oauthRig(t, ms, gg)
	r2.s.who = nil
	w = r2.do(http.MethodPost, "/v1/capabilities", asHolder("m"), mintBody(map[string]any{"user": "me@example.org", "kept": map[string]any{"refresh_token": "rt-1", "provider": "microsoft"}}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"refresh_token":"rt-2"`) {
		t.Fatalf("mint with the kept token: %d %s", w.Code, w.Body)
	}
	// A kept token the provider refuses is a 502 with a sentence.
	w = r2.do(http.MethodPost, "/v1/capabilities", asHolder("m3"), mintBody(map[string]any{"user": "me@example.org", "kept": map[string]any{"refresh_token": "rt-revoked", "provider": "microsoft"}}))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "no longer accepts") {
		t.Fatalf("a refused kept token: %d %s", w.Code, w.Body)
	}
}

// The Google path goes through the sdk's refresh, with no scope; and the
// sign-in must be for the address the holder typed, on the grant path and
// on the kept path alike.
func TestGoogleSignInAndRefresh(t *testing.T) {
	ms, gg := newFakeIdP(t, "microsoft", true), newFakeIdP(t, "google", false)
	r := oauthRig(t, ms, gg)
	r.identity = "me@workspace.example"
	grant := signIn(t, r, gg, "google")
	if !strings.Contains(gg.scopeSeen, "drive.readonly") || !strings.Contains(gg.scopeSeen, "drive.file") {
		t.Fatalf("the scopes asked of Google: %q", gg.scopeSeen)
	}
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("g"), mintBody(map[string]any{"user": "ME@workspace.example", "grant": grant}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"refresh_token":"rt-1"`) || !strings.Contains(w.Body.String(), `"provider":"google"`) {
		t.Fatalf("mint: %d %s", w.Code, w.Body)
	}
	acct, _ := r.s.credStore().Get(context.Background(), "g")
	if acct.Provider != cloud.ProviderGoogle || acct.User != "me@workspace.example" {
		t.Fatalf("kept: %+v", acct)
	}
	acct.Expiry = time.Now().Add(-time.Minute)
	_ = r.s.credStore().Put(context.Background(), "g", acct)
	if w := r.call(t, "g", "account", `{}`); w.Code != http.StatusOK || gg.refreshes != 1 {
		t.Fatalf("refreshed through the sdk: %d %s refreshes=%d", w.Code, w.Body, gg.refreshes)
	}
	// Another account signed in: refused, nothing kept.
	r.identity = "other@workspace.example"
	grant = signIn(t, r, gg, "google")
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("g2"), mintBody(map[string]any{"user": "me@workspace.example", "grant": grant}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "other@workspace.example") {
		t.Fatalf("another account: %d %s", w.Code, w.Body)
	}
	if _, err := r.s.credStore().Get(context.Background(), "g2"); err == nil {
		t.Fatal("nothing should have been kept")
	}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("g2"), mintBody(map[string]any{"user": "me@workspace.example", "kept": map[string]any{"refresh_token": "rt-1", "provider": "google"}}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "other@workspace.example") {
		t.Fatalf("a kept token for another account: %d %s", w.Code, w.Body)
	}
}

// clients builds a settings value with either client present.
func clients(ms, gg bool) config.Config {
	c := config.Config{}
	if ms {
		c.MicrosoftClientID, c.MicrosoftClientSecret = "microsoft-cid", "microsoft-secret"
	}
	if gg {
		c.GoogleClientID, c.GoogleClientSecret = "google-cid", "google-secret"
	}
	return c
}
