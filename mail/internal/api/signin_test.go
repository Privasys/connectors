// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/mail/internal/config"
	"github.com/Privasys/connectors/mail/internal/imapdrv"
	"github.com/Privasys/connectors/mail/internal/mail"
	"github.com/Privasys/connectors/mail/internal/store"
	"github.com/Privasys/connectors/sdk/oauth"
	"github.com/Privasys/connectors/sdk/provider"
)

// fakeIdP is an authorisation server and token endpoint for one provider:
// it issues a code for any sign-in, exchanges it for tokens once with an ID
// token naming `identity`, refreshes rt-1 and refuses every other refresh
// token. The Microsoft one insists the scope is named again on a refresh,
// which is what that endpoint wants, and rotates the refresh token.
type fakeIdP struct {
	srv       *httptest.Server
	name      string
	identity  string
	code      string
	scopeSeen string
	refreshes int
	microsoft bool
}

func newFakeIdP(t *testing.T, name, identity string, microsoft bool) *fakeIdP {
	t.Helper()
	p := &fakeIdP{name: name, identity: identity, microsoft: microsoft}
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": name + "-at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600,
				"id_token": fakeIDToken(p.identity, microsoft),
			})
		case "refresh_token":
			p.refreshes++
			if microsoft && !strings.Contains(r.Form.Get("scope"), "IMAP.AccessAsUser.All") {
				http.Error(w, `{"error":"invalid_request","error_description":"scope is required"}`, http.StatusBadRequest)
				return
			}
			if r.Form.Get("refresh_token") != "rt-1" {
				http.Error(w, `{"error":"invalid_grant","error_description":"The refresh token has expired or been revoked."}`, http.StatusBadRequest)
				return
			}
			out := map[string]any{"access_token": name + "-at-2", "token_type": "Bearer", "expires_in": 3600}
			if microsoft {
				out["refresh_token"] = "rt-2" // Microsoft rotates; Google does not
			}
			_ = json.NewEncoder(w).Encode(out)
		}
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// fakeIDToken is a JWT-shaped ID token, unsigned: the connector reads the
// claims and does not check the signature, and says why. Google names the
// address in `email`; a Microsoft work account may name it only in
// `preferred_username`.
func fakeIDToken(identity string, microsoft bool) string {
	claims := map[string]string{"email": identity}
	if microsoft {
		claims = map[string]string{"preferred_username": identity}
	}
	payload, _ := json.Marshal(claims)
	seg := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	return seg([]byte(`{"alg":"none"}`)) + "." + seg(payload) + "." + seg([]byte("sig"))
}

// rig is a connector over fakes: the two providers, every mailbox
// accepting, and every dial recorded (a sign-in's dial carries its bearer
// as "bearer:<token>" in Password, see acceptingMailbox).
type rig struct {
	s      *Server
	opened *[]imapdrv.Config
}

// last is the most recent dial.
func (r *rig) last() imapdrv.Config { return (*r.opened)[len(*r.opened)-1] }

func oauthRig(t *testing.T, gg, ms *fakeIdP) *rig {
	t.Helper()
	s := freshServer(t)
	r := &rig{s: s, opened: acceptingMailbox(s)}
	s.flows = oauth.NewMulti("mail.mailbox")
	for slug, p := range map[string]struct {
		prov oauth.Provider
		fake *fakeIdP
	}{string(provider.Google): {google, gg}, string(provider.Microsoft): {microsoft, ms}} {
		pv := p.prov
		pv.AuthURL, pv.TokenURL = p.fake.srv.URL+"/auth", p.fake.srv.URL+"/token"
		f := s.flows.Add(slug, pv)
		f.Identify = s.identify
		f.HTTPClient = p.fake.srv.Client()
	}
	s.microsoftTokenURL = ms.srv.URL + "/token"
	s.http = ms.srv.Client()
	s.applyConfig(clients(true, true))
	return r
}

func clients(gg, ms bool) config.Config {
	c := config.Config{}
	if gg {
		c.GoogleClientID, c.GoogleClientSecret = "google-cid", "google-secret"
	}
	if ms {
		c.MicrosoftClientID, c.MicrosoftClientSecret = "microsoft-cid", "microsoft-secret"
	}
	return c.Normalised()
}

func (r *rig) do(method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Host = "mail.apps.example"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.s.Routes().ServeHTTP(w, req)
	return w
}

func asHolder(sub string) map[string]string { return map[string]string{RelaySubjectHeader: sub} }

func asUser(sub string) map[string]string {
	return map[string]string{SubjectHeader: sub, PeerAppHeader: testApp}
}

func mintBody(setup map[string]any) string {
	req := map[string]any{
		"nonce": "n-1", "subject_app_id": testApp, "kind": "mail.mailbox",
		"permissions": []string{"read"}, "expires_unix": time.Now().Add(24 * time.Hour).Unix(),
	}
	if setup != nil {
		req["setup"] = setup
	}
	b, _ := json.Marshal(req)
	return string(b)
}

// signIn plays the wallet and the browser for one provider: start, the
// provider, the callback, and returns the grant code the wallet was sent
// back with.
func signIn(t *testing.T, r *rig, p *fakeIdP, slug string) string {
	t.Helper()
	w := r.do(http.MethodGet, "/v1/oauth/start?kind=mail.mailbox&provider="+slug+"&redirect_uri=privasys-wallet%3A%2F%2Fsetup%2Fcallback&nonce=abcdefgh12345678", nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("start %s: %d %s", slug, w.Code, w.Body)
	}
	req, _ := http.NewRequest(http.MethodGet, w.Header().Get("Location"), nil)
	res, err := p.srv.Client().Transport.RoundTrip(req)
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

// With a client configured, the second step for a Google or Microsoft
// address is the button, with the provider on its start URL, and still no
// password anywhere.
func TestSecondStepIsTheButtonOncePerProviderIsConfigured(t *testing.T) {
	r := oauthRig(t, newFakeIdP(t, "google", "me@gmail.com", false), newFakeIdP(t, "microsoft", "me@outlook.com", true))
	for user, want := range map[string]string{"me@gmail.com": "google", "me@outlook.com": "microsoft"} {
		w := r.do(http.MethodPost, "/v1/capabilities", asHolder("h"), mintBody(map[string]any{"user": user}))
		out := w.Body.String()
		if w.Code != http.StatusPreconditionRequired || !strings.Contains(out, `"Continue with `) ||
			!strings.Contains(out, `https://mail.apps.example/v1/oauth/start?kind=mail.mailbox`) || !strings.Contains(out, "provider="+want) {
			t.Fatalf("%s: the second step is the button: %d %s", user, w.Code, out)
		}
		if strings.Contains(out, "password") {
			t.Fatalf("%s: never a password for a sign-in provider: %s", user, out)
		}
	}
	// A provider without a client is the honest 428 even when the other is
	// configured, and the setup route says the same as the mint.
	r.s.applyConfig(clients(true, false))
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("h"), mintBody(map[string]any{"user": "me@outlook.com"}))
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), "no Microsoft sign-in configured") || strings.Contains(w.Body.String(), "x-privasys-oauth") {
		t.Fatalf("unconfigured provider: %d %s", w.Code, w.Body)
	}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("h"), mintBody(map[string]any{"user": "me@gmail.com"}))
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), "provider=google") {
		t.Fatalf("the other provider still offers its button: %d %s", w.Code, w.Body)
	}
}

// The whole Google path: sign in, mint with the grant, the token set is
// proved against the mailbox and kept, the wallet keeps the refresh token;
// a tool call dials with the bearer and refreshes it when it has expired;
// then a restart, the wallet sends the token back, and the mailbox is
// connected without a browser. A kept token Google refuses is a 502.
func TestGoogleSignInMintAndKeptToken(t *testing.T) {
	gg, ms := newFakeIdP(t, "google", "Me@gmail.com", false), newFakeIdP(t, "microsoft", "me@outlook.com", true)
	r := oauthRig(t, gg, ms)
	grant := signIn(t, r, gg, "google")
	if !strings.Contains(gg.scopeSeen, "https://mail.google.com/") || !strings.Contains(gg.scopeSeen, "email") {
		t.Fatalf("the scopes asked of Google: %q", gg.scopeSeen)
	}

	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("g"), mintBody(map[string]any{"user": "me@gmail.com", "grant": grant}))
	if w.Code != http.StatusOK {
		t.Fatalf("mint with the grant: %d %s", w.Code, w.Body)
	}
	var got struct {
		Keep          map[string]string `json:"keep"`
		ServiceResult map[string]string `json:"service_result"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Keep["refresh_token"] != "rt-1" || got.ServiceResult["account"] != "me@gmail.com" {
		t.Fatalf("the wallet keeps the refresh token and learns the mailbox: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "at-1") {
		t.Fatal("the access token was handed out")
	}
	acct, err := r.s.credStore().Get(context.Background(), "g")
	if err != nil || acct.Provider != store.ProviderGoogle || acct.Host != "imap.gmail.com:993" || acct.RefreshToken != "rt-1" || acct.AccessToken != "google-at-1" || acct.Secret != "" {
		t.Fatalf("kept: %+v %v", acct, err)
	}
	// The probe entered the mailbox at Gmail with the access token, as the
	// typed address.
	if probe := r.last(); probe.Host != "imap.gmail.com:993" || probe.User != "me@gmail.com" || probe.Password != "bearer:google-at-1" {
		t.Fatalf("the probe: %+v", probe)
	}
	// The grant is single use.
	if w := r.do(http.MethodPost, "/v1/capabilities", asHolder("g2"), mintBody(map[string]any{"user": "me@gmail.com", "grant": grant})); w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), "already used") {
		t.Fatalf("a used grant is one more sign-in: %d %s", w.Code, w.Body)
	}
	// A tool call dials with the bearer, and refreshes it when it has
	// expired. Google rotates nothing, so rt-1 stays.
	if w := r.do(http.MethodPost, "/tools/list_messages", asUser("g"), `{}`); w.Code != http.StatusOK {
		t.Fatalf("a Google mailbox serves: %d %s", w.Code, w.Body)
	}
	acct.Expiry = time.Now().Add(-time.Minute)
	_ = r.s.credStore().Put(context.Background(), "g", acct)
	r.s.dropConn("g")
	if w := r.do(http.MethodPost, "/tools/list_messages", asUser("g"), `{}`); w.Code != http.StatusOK {
		t.Fatalf("after an expiry: %d %s", w.Code, w.Body)
	}
	if last := r.last(); gg.refreshes != 1 || last.Password != "bearer:google-at-2" {
		t.Fatalf("the expired token should have been refreshed once: refreshes=%d dial=%+v", gg.refreshes, last)
	}
	if acct, _ := r.s.credStore().Get(context.Background(), "g"); acct.AccessToken != "google-at-2" || acct.RefreshToken != "rt-1" {
		t.Fatalf("the refreshed token goes back into memory: %+v", acct)
	}

	// A restart: the wallet sends what it kept, no browser.
	r2 := oauthRig(t, gg, ms)
	w = r2.do(http.MethodPost, "/v1/capabilities", asHolder("g"), mintBody(map[string]any{"user": "me@gmail.com", "kept": map[string]any{"refresh_token": "rt-1"}}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"refresh_token":"rt-1"`) {
		t.Fatalf("mint with the kept token: %d %s", w.Code, w.Body)
	}
	if acct, err := r2.s.credStore().Get(context.Background(), "g"); err != nil || acct.AccessToken != "google-at-2" {
		t.Fatalf("connected from the kept token: %+v %v", acct, err)
	}
	// A kept token the provider refuses is a 502 with a sentence, and
	// nothing is kept.
	w = r2.do(http.MethodPost, "/v1/capabilities", asHolder("g3"), mintBody(map[string]any{"user": "me@gmail.com", "kept": map[string]any{"refresh_token": "rt-revoked"}}))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "no longer accepts") {
		t.Fatalf("a refused kept token: %d %s", w.Code, w.Body)
	}
	if _, err := r2.s.credStore().Get(context.Background(), "g3"); err == nil {
		t.Fatal("nothing may be kept for a refused token")
	}
}

// The Microsoft path differs in two places: the refresh names the scope
// again, and it rotates the refresh token, so the newest one is what goes
// back to the wallet at the next mint.
func TestMicrosoftSignInRefreshesWithScopeAndRotates(t *testing.T) {
	gg, ms := newFakeIdP(t, "google", "me@gmail.com", false), newFakeIdP(t, "microsoft", "me@outlook.com", true)
	r := oauthRig(t, gg, ms)
	grant := signIn(t, r, ms, "microsoft")
	if !strings.Contains(ms.scopeSeen, "offline_access") || !strings.Contains(ms.scopeSeen, "https://outlook.office.com/IMAP.AccessAsUser.All") {
		t.Fatalf("the scopes asked of Microsoft: %q", ms.scopeSeen)
	}
	if strings.Contains(ms.scopeSeen, "User.Read") || strings.Contains(ms.scopeSeen, "graph.microsoft.com") {
		t.Fatalf("a Graph scope beside the IMAP one is a second resource, which Microsoft refuses: %q", ms.scopeSeen)
	}
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("m"), mintBody(map[string]any{"user": "me@outlook.com", "grant": grant}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"refresh_token":"rt-1"`) {
		t.Fatalf("mint with the grant: %d %s", w.Code, w.Body)
	}
	acct, _ := r.s.credStore().Get(context.Background(), "m")
	if acct.Provider != store.ProviderMicrosoft || acct.Host != "outlook.office365.com:993" || acct.AccessToken != "microsoft-at-1" {
		t.Fatalf("kept: %+v", acct)
	}
	acct.Expiry = time.Now().Add(-time.Minute)
	_ = r.s.credStore().Put(context.Background(), "m", acct)
	r.s.dropConn("m")
	if w := r.do(http.MethodPost, "/tools/list_messages", asUser("m"), `{}`); w.Code != http.StatusOK {
		t.Fatalf("after an expiry: %d %s", w.Code, w.Body)
	}
	if last := r.last(); ms.refreshes != 1 || last.Password != "bearer:microsoft-at-2" || last.Host != "outlook.office365.com:993" {
		t.Fatalf("refreshed once with the scope: refreshes=%d dial=%+v", ms.refreshes, last)
	}
	if acct, _ := r.s.credStore().Get(context.Background(), "m"); acct.RefreshToken != "rt-2" {
		t.Fatalf("the rotated refresh token is the one kept: %+v", acct)
	}
	// A restart: the wallet sends rt-1 (what it was last told), the refresh
	// rotates it again, and the wallet is told the newest.
	r2 := oauthRig(t, gg, ms)
	w = r2.do(http.MethodPost, "/v1/capabilities", asHolder("m"), mintBody(map[string]any{"user": "me@outlook.com", "kept": map[string]any{"refresh_token": "rt-1"}}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"refresh_token":"rt-2"`) {
		t.Fatalf("mint with the kept token hands back the newest: %d %s", w.Code, w.Body)
	}
	// A refresh Microsoft refuses at a tool call sends the agent to the
	// holder's device.
	acct, _ = r2.s.credStore().Get(context.Background(), "m")
	acct.RefreshToken, acct.Expiry = "rt-revoked", time.Now().Add(-time.Minute)
	_ = r2.s.credStore().Put(context.Background(), "m", acct)
	r2.s.dropConn("m")
	w = r2.do(http.MethodPost, "/tools/list_messages", asUser("m"), `{}`)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "request_access") || !strings.Contains(w.Body.String(), "ask_again") {
		t.Fatalf("a refused refresh at a tool call: %d %s", w.Code, w.Body)
	}
}

// The sign-in must be for the address the holder typed: a token for another
// account would open another mailbox under this holder's name.
func TestSignInForAnotherAddressIsRefused(t *testing.T) {
	gg, ms := newFakeIdP(t, "google", "other@gmail.com", false), newFakeIdP(t, "microsoft", "other@outlook.com", true)
	r := oauthRig(t, gg, ms)
	for user, p := range map[string]struct {
		fake *fakeIdP
		slug string
	}{"me@gmail.com": {gg, "google"}, "me@outlook.com": {ms, "microsoft"}} {
		grant := signIn(t, r, p.fake, p.slug)
		w := r.do(http.MethodPost, "/v1/capabilities", asHolder("h"), mintBody(map[string]any{"user": user, "grant": grant}))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "other@") {
			t.Fatalf("%s: a sign-in for another account: %d %s", user, w.Code, w.Body)
		}
		if _, err := r.s.credStore().Get(context.Background(), "h"); err == nil {
			t.Fatal("nothing may be kept for a mismatched sign-in")
		}
	}
}

// A sign-in that opens at the provider but not at the mailbox (IMAP off for
// the account, say) is refused before anything is kept.
func TestSignInIsProvedAgainstTheMailbox(t *testing.T) {
	gg, ms := newFakeIdP(t, "google", "me@gmail.com", false), newFakeIdP(t, "microsoft", "me@outlook.com", true)
	r := oauthRig(t, gg, ms)
	r.s.open = func(context.Context, imapdrv.Config) (mail.Driver, error) {
		return nil, fmt.Errorf("%w: XOAUTH2 400", imapdrv.ErrLogin)
	}
	grant := signIn(t, r, gg, "google")
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("h"), mintBody(map[string]any{"user": "me@gmail.com", "grant": grant}))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "would not open") {
		t.Fatalf("an unprovable token set: %d %s", w.Code, w.Body)
	}
	if _, err := r.s.credStore().Get(context.Background(), "h"); err == nil {
		t.Fatal("an unproven token set was kept")
	}
}

// The address is read from the ID token: `email` first, Microsoft's
// `preferred_username` when that is all a work account carries, and a token
// naming neither is an error rather than an empty identity that would match
// anything.
func TestIDTokenAddress(t *testing.T) {
	if got, err := idTokenAddress(fakeIDToken("Me@Example.org", false)); err != nil || got != "me@example.org" {
		t.Fatalf("email claim: %q %v", got, err)
	}
	if got, err := idTokenAddress(fakeIDToken("me@tenant.example", true)); err != nil || got != "me@tenant.example" {
		t.Fatalf("preferred_username claim: %q %v", got, err)
	}
	for _, bad := range []string{"", "not.a.jwt.at.all", fakeIDToken("", false), fakeIDToken("nobody", true)} {
		if got, err := idTokenAddress(bad); err == nil {
			t.Fatalf("%q should not name an address, got %q", bad, got)
		}
	}
}
