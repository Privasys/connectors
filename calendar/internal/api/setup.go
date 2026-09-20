// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// Connecting an account happens in one place: the wallet's approval screen.
//
// The wallet asks for the address first, alone (428), because what comes
// next depends on it. For a Google account (Google's own domains, or a domain
// whose MX is Google) the second step is one button: the wallet opens this
// service's /v1/oauth/start in an authentication session, the holder signs
// in with Google in their browser, and only a one-time grant code comes back
// to the wallet, which sends it with the mint. For any other account the
// second step is an app password, proved against the server found from the
// address, exactly as the mail connector does it.
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
	"github.com/Privasys/connectors/calendar/internal/store"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/oauth"
)

type setup struct{ s *Server }

// addressElicit is the first step: the address alone, so the second step
// can be drawn for it.
func addressElicit() map[string]any {
	return connector.Elicit(
		"Connect your calendar. Enter the email address of the account; what you enter goes to the calendar connector's enclave and is kept by this device, the service stores nothing.",
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

// googleElicit is the second step for a Google account: one button. The
// wallet draws it from x-privasys-oauth and fills `grant` with the code the
// sign-in sent back.
func (p *setup) googleElicit(r *http.Request, user string) map[string]any {
	return connector.Elicit(
		strings.TrimSpace(user)+" is a Google account. Sign in with Google to connect its calendar; the sign-in happens in your browser and only a one-time code comes back to this device.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user":  map[string]any{"type": "string", "title": "Email address", "format": "email", "default": strings.TrimSpace(user)},
				"grant": p.s.flow.SchemaProperty(r),
			},
			"required": []string{"user", "grant"},
		})
}

func str(answers map[string]any, k string) string {
	v, _ := answers[k].(string)
	return strings.TrimSpace(v)
}

// Question is the step the answers so far call for.
func (p *setup) Question(r *http.Request, answers map[string]any) map[string]any {
	ctx := r.Context()
	user := str(answers, "user")
	if user == "" || discover.Domain(user) == "" {
		return addressElicit()
	}
	if p.s.resolver.IsGoogle(ctx, user) {
		return p.googleElicit(r, user)
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
	if kept, ok := answers["kept"].(map[string]any); ok {
		if rt := str(kept, "refresh_token"); rt != "" {
			return p.connectGoogleKept(ctx, sub, user, rt)
		}
	}
	if p.s.resolver.IsGoogle(ctx, user) {
		return p.connectGoogle(r, sub, user, str(answers, "grant"))
	}
	return p.connectPassword(ctx, sub, user, str(answers, "password"), str(answers, "host"))
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

// ---------------------------------------------------------------- google

// connectGoogle redeems the grant code the wallet was sent back with, proves
// the tokens against the calendar, keeps them, and hands the wallet the
// refresh token to keep.
func (p *setup) connectGoogle(r *http.Request, sub, user, grant string) (map[string]any, error) {
	ctx := r.Context()
	if !p.s.flow.Configured() {
		return nil, connector.Errorf(http.StatusServiceUnavailable,
			"this deployment has no Google OAuth client configured, so a Google account cannot be connected here")
	}
	if grant == "" {
		return nil, &connector.ElicitError{Elicit: p.googleElicit(r, user)}
	}
	issued, ok := p.s.flow.Redeem(grant)
	if !ok {
		// Unknown, used or expired: one more sign-in, said plainly.
		q := p.googleElicit(r, user)
		q["message"] = "The sign-in code is unknown, already used or expired. Sign in with Google again."
		return nil, &connector.ElicitError{Elicit: q}
	}
	if issued.Identity != "" && !strings.EqualFold(issued.Identity, user) {
		return nil, connector.Errorf(http.StatusBadRequest,
			"the Google sign-in was for %s, not %s; enter the address you sign in with", issued.Identity, user)
	}
	if issued.RefreshToken == "" {
		return nil, connector.Errorf(http.StatusBadGateway,
			"Google issued no refresh token for this sign-in, so the connection would not outlive an hour; remove this app from the Google account's connected apps and sign in again")
	}
	return p.keepGoogle(ctx, sub, user, issued.Tokens)
}

// connectGoogleKept uses the refresh token the wallet kept instead of a
// browser: mint an access token, prove it, keep it.
func (p *setup) connectGoogleKept(ctx context.Context, sub, user, refreshToken string) (map[string]any, error) {
	if !p.s.flow.Configured() {
		return nil, connector.Errorf(http.StatusServiceUnavailable,
			"this deployment has no Google OAuth client configured, so a Google account cannot be connected here")
	}
	t, err := p.s.flow.Refresh(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, oauth.ErrRefused) {
			return nil, connector.Errorf(http.StatusBadGateway, "Google no longer accepts the saved sign-in for %s; sign in again", user)
		}
		return nil, connector.Errorf(http.StatusBadGateway, "Google could not be reached to renew the sign-in: %v", err)
	}
	return p.keepGoogle(ctx, sub, user, t)
}

// keepGoogle proves the tokens with one call to the calendar and keeps the
// credential. What goes back to the wallet is the refresh token, and only
// that: the access token is minutes from expiring and this service mints
// the next one itself.
func (p *setup) keepGoogle(ctx context.Context, sub, user string, t oauth.Tokens) (map[string]any, error) {
	endpoint := discover.GoogleEndpoint(user)
	principal, _ := url.Parse(endpoint)
	acct := store.Account{
		Provider: store.ProviderGoogle, Endpoint: endpoint, Principal: principal.Path, User: user, LinkedAt: time.Now(),
		RefreshToken: t.RefreshToken, AccessToken: t.AccessToken, Expiry: t.Expiry,
	}
	drv, err := p.s.open(ctx, caldavdrv.Config{
		Endpoint: endpoint, Principal: principal.Path, User: user, HTTPClient: p.s.http,
		Token: func(context.Context) (string, error) { return t.AccessToken, nil },
	})
	if err != nil {
		return nil, connector.Errorf(http.StatusBadGateway, "signed in, but Google's calendar would not open for %s: %v", user, err)
	}
	_ = drv.Close()
	if err := p.keep(ctx, sub, acct); err != nil {
		return nil, err
	}
	return map[string]any{"refresh_token": t.RefreshToken}, nil
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

// identify reads the address of the account that just signed in, at the
// OAuth callback, so the mint can check it is the address the holder typed.
func (s *Server) identify(ctx context.Context, t oauth.Tokens) (string, error) {
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
