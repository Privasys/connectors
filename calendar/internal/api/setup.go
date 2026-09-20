// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// Connecting an account happens in one place: the wallet's approval screen.
//
// The wallet asks for the address first, alone (428), because everything
// depends on it: the address says who hosts the account, and so which
// server, which authorisation, and whether the account can be connected
// here at all. A Google address (Google's own domains, or a domain whose
// MX is Google) gets one button, Continue with Google; a Microsoft address
// gets Continue with Microsoft, because Microsoft serves no CalDAV; any
// other address gets an app password, proved against the server found from
// the address. A holder is never asked to pick a provider the domain
// already names, and a provider whose sign-in client is not configured on
// this deployment is said plainly, with nothing to fill.
//
// For a sign-in, the wallet opens this service's /v1/oauth/start in an
// authentication session, the holder signs in in their browser, and only a
// one-time grant code comes back to the wallet, which sends it with the
// mint. The mint refuses a sign-in for any address but the one typed, so
// the address is bound to the account, not decorative.
//
// A password is what the holder typed, and their device already keeps it.
// A refresh token is not: it is the one thing this service asks the wallet
// to keep for it (`keep`), and a later mint carries it back as
// `setup.kept.refresh_token` so nobody has to sign in again after a restart.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Privasys/connectors/calendar/internal/caldavdrv"
	"github.com/Privasys/connectors/calendar/internal/discover"
	"github.com/Privasys/connectors/calendar/internal/graphdrv"
	"github.com/Privasys/connectors/calendar/internal/store"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/oauth"
	"github.com/Privasys/connectors/sdk/provider"
)

type setup struct{ s *Server }

// addressElicit is the first step: the address alone, so the second step
// can be drawn for it.
func addressElicit() map[string]any {
	return connector.Elicit(
		"Connect your calendar. Enter the email address of the account; the connector finds who hosts it and asks you to sign in there, or for an app password where there is no sign-in. What you enter goes to the calendar connector's enclave and is kept by this device, the service stores nothing.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user": map[string]any{"type": "string", "title": "Email address", "format": "email"},
			},
			"required": []string{"user"},
		})
}

// passwordElicit is the second step for an app-password account.
func passwordElicit(user string) map[string]any {
	return connector.Elicit(
		"Enter an app password for "+strings.TrimSpace(user)+". Never your sign-in password: your provider issues app passwords under its security settings (iCloud: Sign-In and Security > App-Specific Passwords; Fastmail: Settings > Privacy and Security > Integrations).",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user":     map[string]any{"type": "string", "title": "Email address", "format": "email", "default": strings.TrimSpace(user)},
				"password": map[string]any{"type": "string", "title": "App password", "format": "password"},
			},
			"required": []string{"user", "password"},
		},
		"password")
}

// hostElicit is the follow-up when the server could not be found.
func hostElicit(user string, tried []string) map[string]any {
	return connector.Elicit(
		"The calendar server for "+strings.TrimSpace(user)+" could not be found automatically.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host": map[string]any{"type": "string", "title": "CalDAV server",
					"description": "As a URL, for example https://calendar.example.com/dav/. Tried: " + strings.Join(tried, ", ") + "."},
			},
			"required": []string{"host"},
		})
}

// signInElicit is the second step for a Google or a Microsoft address: one
// button. The wallet draws it from x-privasys-oauth and fills `grant` with
// the code the sign-in sent back.
func (p *setup) signInElicit(r *http.Request, who provider.Provider, user string) map[string]any {
	return connector.Elicit(
		strings.TrimSpace(user)+" is a "+who.Name()+" account. Sign in with "+who.Name()+" to connect its calendar; the sign-in happens in your browser and only a one-time code comes back to this device.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user":  map[string]any{"type": "string", "title": "Email address", "format": "email", "default": strings.TrimSpace(user)},
				"grant": p.s.flows.SchemaProperty(r, slugOf(who)),
			},
			"required": []string{"user", "grant"},
		})
}

// notConfiguredElicit is the honest answer for a provider this deployment
// has no sign-in client for: a sentence, and nothing to fill.
func notConfiguredElicit(who provider.Provider, user string) map[string]any {
	return connector.Elicit(
		strings.TrimSpace(user)+" is a "+who.Name()+" account, and this deployment of the calendar connector has no "+who.Name()+" sign-in configured, so it cannot connect it. Ask whoever runs it to configure a "+who.Name()+" client.",
		map[string]any{"type": "object", "properties": map[string]any{}})
}

// slugOf is the sign-in flow a provider runs under; "" for one without.
func slugOf(who provider.Provider) string {
	switch who {
	case provider.Google:
		return store.ProviderGoogle
	case provider.Microsoft:
		return store.ProviderMicrosoft
	}
	return ""
}

func str(answers map[string]any, k string) string {
	v, _ := answers[k].(string)
	return strings.TrimSpace(v)
}

// hostOf says who hosts the typed address. A kept sign-in names its
// provider too (`kept.provider`), and that word wins: the sign-in already
// proved it, and a resolver that cannot be reached at that moment must not
// turn a kept Google token into a password question.
func (p *setup) hostOf(ctx context.Context, answers map[string]any, user string) provider.Provider {
	if kept, ok := answers["kept"].(map[string]any); ok {
		switch str(kept, "provider") {
		case store.ProviderGoogle:
			return provider.Google
		case store.ProviderMicrosoft:
			return provider.Microsoft
		}
	}
	return p.s.who.Of(ctx, user)
}

// Question is the step the answers so far call for.
func (p *setup) Question(r *http.Request, answers map[string]any) map[string]any {
	user := str(answers, "user")
	if user == "" || discover.Domain(user) == "" {
		return addressElicit()
	}
	who := p.hostOf(r.Context(), answers, user)
	if slug := slugOf(who); slug != "" {
		if !p.s.flows.Flow(slug).Configured() {
			return notConfiguredElicit(who, user)
		}
		return p.signInElicit(r, who, user)
	}
	return passwordElicit(user)
}

// Connect proves the answers and keeps the credential.
func (p *setup) Connect(r *http.Request, sub string, answers map[string]any) (map[string]any, error) {
	ctx := r.Context()
	user := str(answers, "user")
	if user == "" || discover.Domain(user) == "" {
		return nil, &connector.ElicitError{Elicit: addressElicit()}
	}
	who := p.hostOf(ctx, answers, user)
	slug := slugOf(who)
	if slug == "" {
		return p.connectPassword(ctx, sub, user, str(answers, "password"), str(answers, "host"))
	}
	if !p.s.flows.Flow(slug).Configured() {
		return nil, &connector.ElicitError{Elicit: notConfiguredElicit(who, user)}
	}
	if kept, ok := answers["kept"].(map[string]any); ok {
		if rt := str(kept, "refresh_token"); rt != "" {
			return p.connectKept(ctx, sub, who, user, rt)
		}
	}
	return p.connectGrant(r, sub, who, user, str(answers, "grant"))
}

// ---------------------------------------------------------------- password

func (p *setup) connectPassword(ctx context.Context, sub, user, password, host string) (map[string]any, error) {
	if password == "" {
		return nil, &connector.ElicitError{Elicit: passwordElicit(user)}
	}
	var candidates []string
	if host != "" {
		u := host
		if !strings.Contains(u, "://") {
			u = "https://" + u
		}
		if parsed, err := url.Parse(u); err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return nil, connector.Errorf(http.StatusBadRequest, "the server must be an https URL")
		}
		candidates = []string{u}
	} else {
		candidates = p.s.resolver.Candidates(ctx, user)
	}
	var tried []string
	for _, endpoint := range candidates {
		tried = append(tried, endpoint)
		drv, err := p.s.open(ctx, caldavdrv.Config{Endpoint: endpoint, User: user, Password: password, HTTPClient: p.s.http})
		if err == nil {
			_ = drv.Close()
			return nil, p.keep(ctx, sub, store.Account{
				Provider: store.ProviderCalDAV, Endpoint: endpoint, User: user, Secret: password, LinkedAt: time.Now(),
			})
		}
		if errors.Is(err, caldavdrv.ErrLogin) {
			// The server answered: the details are wrong, not the server.
			return nil, connector.Errorf(http.StatusBadGateway, "the calendar server refused these details: %v", err)
		}
		if host != "" {
			return nil, connector.Errorf(http.StatusBadGateway, "the calendar server at %s could not be used: %v", host, err)
		}
	}
	return nil, &connector.ElicitError{Elicit: hostElicit(user, tried)}
}

// ---------------------------------------------------------------- sign-in

// connectGrant redeems the grant code the wallet was sent back with, checks
// the sign-in was for the address typed, proves the tokens against the
// calendar, keeps them, and hands the wallet the refresh token to keep.
func (p *setup) connectGrant(r *http.Request, sub string, who provider.Provider, user, grant string) (map[string]any, error) {
	flow := p.s.flows.Flow(slugOf(who))
	if grant == "" {
		return nil, &connector.ElicitError{Elicit: p.signInElicit(r, who, user)}
	}
	issued, ok := flow.Redeem(grant)
	if !ok {
		// Unknown, used or expired: one more sign-in, said plainly.
		q := p.signInElicit(r, who, user)
		q["message"] = "The sign-in code is unknown, already used or expired. Sign in with " + who.Name() + " again."
		return nil, &connector.ElicitError{Elicit: q}
	}
	if issued.Identity != "" && !strings.EqualFold(issued.Identity, user) {
		return nil, connector.Errorf(http.StatusBadRequest,
			"the %s sign-in was for %s, not %s; enter the address you sign in with", who.Name(), issued.Identity, user)
	}
	if issued.RefreshToken == "" {
		return nil, connector.Errorf(http.StatusBadGateway,
			"%s issued no refresh token for this sign-in, so the connection would not outlive an hour; remove this app from the account's connected apps and sign in again", who.Name())
	}
	return p.keepSignIn(r.Context(), sub, who, user, issued.Tokens)
}

// connectKept uses the refresh token the wallet kept instead of a browser:
// mint an access token, prove it, keep it.
func (p *setup) connectKept(ctx context.Context, sub string, who provider.Provider, user, refreshToken string) (map[string]any, error) {
	t, err := p.s.refresh(ctx, slugOf(who), refreshToken)
	if err != nil {
		if errors.Is(err, oauth.ErrRefused) {
			return nil, connector.Errorf(http.StatusBadGateway, "%s no longer accepts the saved sign-in for %s; sign in again", who.Name(), user)
		}
		return nil, connector.Errorf(http.StatusBadGateway, "%s could not be reached to renew the sign-in: %v", who.Name(), err)
	}
	return p.keepSignIn(ctx, sub, who, user, t)
}

// keepSignIn proves the tokens with one call to the calendar and keeps the
// credential. What goes back to the wallet is the refresh token and the
// provider it is for, and only that: the access token is minutes from
// expiring and this service mints the next one itself.
func (p *setup) keepSignIn(ctx context.Context, sub string, who provider.Provider, user string, t oauth.Tokens) (map[string]any, error) {
	acct := store.Account{
		Provider: slugOf(who), User: user, LinkedAt: time.Now(),
		RefreshToken: t.RefreshToken, AccessToken: t.AccessToken, Expiry: t.Expiry,
	}
	bearer := func(context.Context) (string, error) { return t.AccessToken, nil }
	var err error
	switch who {
	case provider.Google:
		acct.Endpoint = discover.GoogleEndpoint(user)
		principal, _ := url.Parse(acct.Endpoint)
		acct.Principal = principal.Path
		var drv interface{ Close() error }
		drv, err = p.s.open(ctx, caldavdrv.Config{
			Endpoint: acct.Endpoint, Principal: acct.Principal, User: user, HTTPClient: p.s.http, Token: bearer,
		})
		if err == nil {
			_ = drv.Close()
		}
	case provider.Microsoft:
		var drv graphDriver
		drv, err = p.s.openGraph(ctx, graphdrv.Config{HTTP: p.s.http, Token: bearer})
		if err == nil {
			// The kept path has no callback probe, so the address is
			// checked here, against what Graph says.
			if live := drv.User(); live != "" && !strings.EqualFold(live, user) {
				return nil, connector.Errorf(http.StatusBadRequest,
					"the Microsoft sign-in was for %s, not %s; enter the address you sign in with", live, user)
			}
			_ = drv.Close()
		}
	}
	if err != nil {
		return nil, connector.Errorf(http.StatusBadGateway, "signed in, but %s's calendar would not open for %s: %v", who.Name(), user, err)
	}
	if err := p.keep(ctx, sub, acct); err != nil {
		return nil, err
	}
	return map[string]any{"refresh_token": t.RefreshToken, "provider": acct.Provider}, nil
}

// keep holds a proven credential in memory and drops any connection opened
// with the previous one.
func (p *setup) keep(ctx context.Context, sub string, acct store.Account) error {
	if err := p.s.credStore().Put(ctx, sub, acct); err != nil {
		return connector.Errorf(http.StatusInternalServerError, "%v", err)
	}
	p.s.dropConn(sub)
	return nil
}

// identifyGoogle reads the address of the account that just signed in, at
// the OAuth callback, so the mint can check it is the address the holder
// typed.
func (s *Server) identifyGoogle(ctx context.Context, t oauth.Tokens) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.userinfo, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	res, err := s.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo: %s", res.Status)
	}
	var info struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&info); err != nil {
		return "", err
	}
	if info.Email == "" {
		return "", errors.New("userinfo names no email")
	}
	return strings.ToLower(info.Email), nil
}

// identifyMicrosoft does the same through Graph, with the driver's own
// probe, so a sign-in that cannot open the calendars is refused before the
// wallet is handed a grant code.
func (s *Server) identifyMicrosoft(ctx context.Context, t oauth.Tokens) (string, error) {
	drv, err := s.openGraph(ctx, graphdrv.Config{HTTP: s.http, Token: func(context.Context) (string, error) { return t.AccessToken, nil }})
	if err != nil {
		return "", err
	}
	defer drv.Close()
	if drv.User() == "" {
		return "", errors.New("graph names no address for the account")
	}
	return drv.User(), nil
}
