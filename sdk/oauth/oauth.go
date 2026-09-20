// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package oauth runs an OAuth 2.0 authorisation for a connector, with the
// wallet holding the browser and the connector holding everything else.
//
// The shape of the deal. A setup schema property declares
// `"x-privasys-oauth": {"provider": "Google", "start_url": "https://<service
// host>/v1/oauth/start?kind=<kind>"}` on a string field. The wallet draws one
// button ("Continue with Google") and, on the tap, opens
// `<start_url>&redirect_uri=<wallet scheme>://setup/callback&nonce=<n>` in an
// authentication session; it refuses a start URL that is not https on the
// service's own host. This package answers that start with a redirect to the
// provider, takes the provider's callback, exchanges the code with the sealed
// client secret and the PKCE verifier, and sends the wallet back to its own
// scheme with a one-time GRANT CODE. The wallet puts the code in the mint's
// `setup`, the connector redeems it (once), proves the tokens with its own
// probe, keeps the credential in memory, and hands the wallet the refresh
// token to keep for it. Nothing here is rendered in a page: the code, the
// tokens and the state travel only in redirects and in memory.
//
// The sdk knows no provider by name. The endpoints, the scopes and any extra
// parameters come from a Provider value the connector supplies, and the
// account identity and the credential shape stay with the connector.
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/connectors/sdk/web"
	"golang.org/x/oauth2"
)

// Provider is one OAuth 2.0 authorisation server, as the connector declares
// it.
type Provider struct {
	// Name is what the wallet's button says: "Continue with <Name>".
	Name     string
	AuthURL  string
	TokenURL string
	// Scopes are what the connector needs for its kind.
	Scopes []string
	// AuthParams are extra query parameters on the authorisation URL. Google
	// issues a refresh token only with access_type=offline and prompt=consent
	// together; that is the connector's to say.
	AuthParams map[string]string
}

// Tokens is a token set, as kept in memory and as handed to the wallet.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

// Issued is what a redeemed grant code carries: the tokens, and the account
// identity the connector's Identify returned at the callback.
type Issued struct {
	Tokens
	Identity string
}

// Paths of the two routes.
const (
	StartPath    = "/v1/oauth/start"
	CallbackPath = "/v1/oauth/callback"
)

// ttl is how long a started sign-in and an issued grant code live: long
// enough to type a password and a second factor, short enough that a code
// left in a log somewhere is worthless by the time anyone reads it.
const ttl = 10 * time.Minute

// Flow runs the authorisation for one provider and one capability kind.
type Flow struct {
	provider Provider
	kind     string

	// Identify, when set, is called at the callback with the fresh tokens
	// and returns the account identity to keep beside them, usually by one
	// call to the provider. An error sends the wallet back with an error
	// rather than a grant.
	Identify func(ctx context.Context, t Tokens) (string, error)

	// HTTPClient reaches the token endpoint; nil is the default client. A
	// test points it at a fake provider.
	HTTPClient *http.Client

	now func() time.Time

	mu           sync.Mutex
	clientID     string
	clientSecret string
	states       map[string]pending
	grants       map[string]issued
}

type pending struct {
	redirect string
	nonce    string
	verifier string
	callback string
	expires  time.Time
}

type issued struct {
	Issued
	expires time.Time
}

// New builds a flow for one provider and one kind.
func New(p Provider, kind string) *Flow {
	return &Flow{
		provider: p, kind: kind, now: time.Now,
		states: map[string]pending{}, grants: map[string]issued{},
	}
}

// SetClient installs the client id and secret from the configuration. The
// secret is sealed exactly as any configured value and never leaves this
// process: it is used at the token endpoint and nowhere else.
func (f *Flow) SetClient(id, secret string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clientID, f.clientSecret = strings.TrimSpace(id), strings.TrimSpace(secret)
}

// Configured reports whether a client has been set.
func (f *Flow) Configured() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clientID != "" && f.clientSecret != ""
}

// ServiceURL is this service's own https origin as the caller reached it,
// for the start URL and the provider's redirect URI. Always https: the
// wallet refuses anything else, and the URI registered at the provider is
// the https one.
func ServiceURL(r *http.Request) string {
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	return "https://" + host
}

// SchemaProperty is the setup schema property that draws the sign-in button:
// a string field the wallet fills with the grant code it was sent back with.
func (f *Flow) SchemaProperty(r *http.Request) map[string]any {
	return map[string]any{
		"type":        "string",
		"title":       "Continue with " + f.provider.Name,
		"description": "Sign in with " + f.provider.Name + " on this device. The sign-in happens in your browser; only a one-time code comes back here.",
		"x-privasys-oauth": map[string]string{
			"provider":  f.provider.Name,
			"start_url": ServiceURL(r) + StartPath + "?kind=" + url.QueryEscape(f.kind),
		},
	}
}

// Routes registers the start and the callback.
func (f *Flow) Routes(m *http.ServeMux) {
	m.HandleFunc("GET "+StartPath, f.start)
	m.HandleFunc("GET "+CallbackPath, f.callback)
}

// A custom app scheme, never http or https: the wallet opens the callback in
// its own authentication session and nothing else may.
var schemeRe = regexp.MustCompile(`^[a-z][a-z0-9.+-]*$`)

// A nonce of 8 to 128 URL-safe characters, echoed back so the wallet can tie
// the callback to the tap that started it.
var nonceRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{8,128}$`)

// validRedirect accepts exactly `<scheme>://setup/callback`.
func validRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Scheme == "http" || u.Scheme == "https" {
		return false
	}
	if !schemeRe.MatchString(u.Scheme) {
		return false
	}
	return u.Host == "setup" && u.Path == "/callback" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// start is public, there is no holder yet: it generates the state and the
// PKCE verifier, remembers where to send the wallet back, and sends the
// browser to the provider.
func (f *Flow) start(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	if q.Get("kind") != f.kind {
		web.WriteErr(w, http.StatusNotFound, "this service signs in for "+f.kind+", not "+q.Get("kind"))
		return
	}
	redirect := q.Get("redirect_uri")
	if !validRedirect(redirect) {
		web.WriteErr(w, http.StatusBadRequest, "redirect_uri must be <app scheme>://setup/callback")
		return
	}
	nonce := q.Get("nonce")
	if !nonceRe.MatchString(nonce) {
		web.WriteErr(w, http.StatusBadRequest, "nonce must be 8 to 128 URL-safe characters")
		return
	}
	cfg, ok := f.config(ServiceURL(r) + CallbackPath)
	if !ok {
		web.WriteErr(w, http.StatusServiceUnavailable, "this deployment has no OAuth client configured for "+f.provider.Name)
		return
	}

	state := random(32)
	verifier := oauth2.GenerateVerifier()
	f.mu.Lock()
	f.sweepLocked()
	f.states[state] = pending{
		redirect: redirect, nonce: nonce, verifier: verifier,
		callback: cfg.RedirectURL, expires: f.now().Add(ttl),
	}
	f.mu.Unlock()

	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	for k, v := range f.provider.AuthParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	http.Redirect(w, r, cfg.AuthCodeURL(state, opts...), http.StatusFound)
}

// callback takes the provider's answer. The state is looked up once; the code
// is exchanged with the sealed secret and the verifier; the tokens go into
// memory under a fresh one-time grant code; and the browser is sent back to
// the wallet with that code, or with a short reason when anything failed.
func (f *Flow) callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	f.mu.Lock()
	f.sweepLocked()
	p, ok := f.states[q.Get("state")]
	delete(f.states, q.Get("state"))
	f.mu.Unlock()
	if !ok {
		// Nowhere to send the browser back to, and no state to name: an
		// unknown or expired sign-in is told to start again from the wallet.
		web.WriteErr(w, http.StatusBadRequest, "this sign-in is unknown or has expired; start it again from your wallet")
		return
	}
	back := func(params url.Values) {
		params.Set("nonce", p.nonce)
		http.Redirect(w, r, p.redirect+"?"+params.Encode(), http.StatusFound)
	}
	if e := q.Get("error"); e != "" {
		back(url.Values{"error": {shortReason(e)}})
		return
	}
	code := q.Get("code")
	if code == "" {
		back(url.Values{"error": {"no_code"}})
		return
	}
	cfg, ok := f.config(p.callback)
	if !ok {
		back(url.Values{"error": {"not_configured"}})
		return
	}
	tok, err := cfg.Exchange(f.ctx(r.Context()), code, oauth2.VerifierOption(p.verifier))
	if err != nil {
		back(url.Values{"error": {"exchange_failed"}})
		return
	}
	t := Tokens{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, Expiry: tok.Expiry}
	identity := ""
	if f.Identify != nil {
		identity, err = f.Identify(r.Context(), t)
		if err != nil {
			back(url.Values{"error": {"probe_failed"}})
			return
		}
	}

	grant := random(32)
	f.mu.Lock()
	f.grants[grant] = issued{Issued: Issued{Tokens: t, Identity: identity}, expires: f.now().Add(ttl)}
	f.mu.Unlock()
	back(url.Values{"grant": {grant}})
}

// Redeem takes the tokens a grant code stands for, once. A second redeem,
// an unknown code and an expired one all answer false.
func (f *Flow) Redeem(code string) (Issued, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked()
	g, ok := f.grants[code]
	delete(f.grants, code)
	if !ok {
		return Issued{}, false
	}
	return g.Issued, true
}

// ErrRefused is the provider refusing a refresh token: it was revoked, or
// issued to another client.
var ErrRefused = errors.New("the provider refused the refresh token")

// Refresh mints an access token from a refresh token the wallet kept. The
// refresh token comes back too: a provider that rotates it answers with a
// new one, and one that does not keeps the old one valid.
func (f *Flow) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return Tokens{}, errors.New("no refresh token")
	}
	cfg, ok := f.config("")
	if !ok {
		return Tokens{}, errors.New("this deployment has no OAuth client configured for " + f.provider.Name)
	}
	tok, err := cfg.TokenSource(f.ctx(ctx), &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		var oe *oauth2.RetrieveError
		if errors.As(err, &oe) {
			return Tokens{}, fmt.Errorf("%w: %s", ErrRefused, strings.TrimSpace(oe.ErrorCode+" "+oe.ErrorDescription))
		}
		return Tokens{}, err
	}
	out := Tokens{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, Expiry: tok.Expiry}
	if out.RefreshToken == "" {
		out.RefreshToken = refreshToken
	}
	return out, nil
}

// config is the oauth2 configuration for one callback URL, or false when no
// client has been set.
func (f *Flow) config(callback string) (*oauth2.Config, bool) {
	f.mu.Lock()
	id, secret := f.clientID, f.clientSecret
	f.mu.Unlock()
	if id == "" || secret == "" {
		return nil, false
	}
	return &oauth2.Config{
		ClientID: id, ClientSecret: secret,
		Endpoint:    oauth2.Endpoint{AuthURL: f.provider.AuthURL, TokenURL: f.provider.TokenURL, AuthStyle: oauth2.AuthStyleInParams},
		RedirectURL: callback,
		Scopes:      f.provider.Scopes,
	}, true
}

// ctx carries the HTTP client the token endpoint is reached with.
func (f *Flow) ctx(ctx context.Context) context.Context {
	if f.HTTPClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, f.HTTPClient)
}

// sweepLocked drops expired sign-ins and grant codes. Called with f.mu held.
func (f *Flow) sweepLocked() {
	now := f.now()
	for k, p := range f.states {
		if now.After(p.expires) {
			delete(f.states, k)
		}
	}
	for k, g := range f.grants {
		if now.After(g.expires) {
			delete(f.grants, k)
		}
	}
}

// shortReason keeps the provider's error code and nothing else: no
// description, no URI, nothing that could carry a payload into the wallet.
func shortReason(e string) string {
	e = strings.ToLower(strings.TrimSpace(e))
	if len(e) > 32 || !regexp.MustCompile(`^[a-z0-9_]+$`).MatchString(e) {
		return "denied"
	}
	return e
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("the random source failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
