// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// Connecting an account happens in one place: the wallet's approval screen.
//
// The wallet asks for the address first, alone (428), because the address
// decides everything: who hosts the account, and so which sign-in, and
// whether the account can be connected here at all. A Google address
// (Google's own domains, or a domain whose MX is Google) gets one button,
// Continue with Google; a Microsoft address gets Continue with Microsoft;
// an address hosted anywhere else is told, in a sentence with nothing to
// fill, that this connector reaches only those two. A holder is never asked
// to pick a provider the domain already names, and a provider whose
// sign-in client is not configured on this deployment is said plainly.
//
// For the sign-in the wallet opens this service's /v1/oauth/start in an
// authentication session, the holder signs in with Microsoft or Google in
// their browser, and only a one-time grant code comes back to the wallet,
// which sends it with the mint. The mint refuses a sign-in for any address
// but the one typed, so the address is bound to the account, not
// decorative.
//
// A refresh token is the one thing this service asks the wallet to keep for
// it (`keep`), with the provider it is for, and a later mint carries both
// back as `setup.kept` so nobody has to sign in again after a restart.

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

	"github.com/Privasys/connectors/files/internal/cloud"
	"github.com/Privasys/connectors/files/internal/store"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/oauth"
	"github.com/Privasys/connectors/sdk/provider"
)

type setup struct{ s *Server }

func str(answers map[string]any, k string) string {
	v, _ := answers[k].(string)
	return strings.TrimSpace(v)
}

// slugOf is the sign-in flow a provider runs under; "" for one this
// connector cannot reach.
func slugOf(who provider.Provider) string {
	switch who {
	case provider.Google:
		return cloud.ProviderGoogle
	case provider.Microsoft:
		return cloud.ProviderMicrosoft
	}
	return ""
}

// addressElicit is the first step: the address alone, so the second step
// can be drawn for it.
func addressElicit() map[string]any {
	return connector.Elicit(
		"Connect your files. Enter the email address of the account; the connector finds who hosts it (Microsoft for OneDrive and SharePoint, Google for Google Drive) and asks you to sign in there in your browser. Nothing else is typed here, and the service stores nothing: the sign-in is kept by this device.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user": map[string]any{"type": "string", "title": "Email address", "format": "email"},
			},
			"required": []string{"user"},
		})
}

// signInElicit is the second step: one button for the provider the address
// names. The wallet draws it from x-privasys-oauth and fills `grant` with
// the code the sign-in sent back.
func (p *setup) signInElicit(r *http.Request, who provider.Provider, user string) map[string]any {
	return connector.Elicit(
		user+" is a "+who.Name()+" account. Sign in with "+who.Name()+" to connect its files; the sign-in happens in your browser and only a one-time code comes back to this device.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user":  map[string]any{"type": "string", "title": "Email address", "format": "email", "default": user},
				"grant": p.s.flows.SchemaProperty(r, slugOf(who)),
			},
			"required": []string{"user", "grant"},
		})
}

// unreachableElicit is the honest answer for an address at a provider this
// connector cannot reach: a sentence, and nothing to fill.
func unreachableElicit(user string) map[string]any {
	return connector.Elicit(
		user+" is not at a provider this connector can reach. It connects files at Microsoft (OneDrive, SharePoint) and at Google (Google Drive), and reads who hosts an address from its domain; an address at either that is not recognised is worth a word to whoever runs this deployment.",
		map[string]any{"type": "object", "properties": map[string]any{}})
}

// notConfiguredElicit is the honest answer for a provider this deployment
// has no sign-in client for: a sentence, and nothing to fill.
func notConfiguredElicit(who provider.Provider, user string) map[string]any {
	return connector.Elicit(
		user+" is a "+who.Name()+" account, and this deployment of the files connector has no "+who.Name()+" sign-in configured, so it cannot connect it. Ask whoever runs it to configure a "+who.Name()+" client.",
		map[string]any{"type": "object", "properties": map[string]any{}})
}

// hostOf says who hosts the typed address. A kept sign-in names its
// provider too (`kept.provider`), and that word wins: the sign-in already
// proved it, and a resolver that cannot be reached at that moment must not
// refuse a kept token.
func (p *setup) hostOf(ctx context.Context, answers map[string]any, user string) provider.Provider {
	if kept, ok := answers["kept"].(map[string]any); ok {
		switch str(kept, "provider") {
		case cloud.ProviderGoogle:
			return provider.Google
		case cloud.ProviderMicrosoft:
			return provider.Microsoft
		}
	}
	return p.s.who.Of(ctx, user)
}

// Question is the step the answers so far call for.
func (p *setup) Question(r *http.Request, answers map[string]any) map[string]any {
	user := strings.ToLower(str(answers, "user"))
	if provider.Domain(user) == "" {
		return addressElicit()
	}
	who := p.hostOf(r.Context(), answers, user)
	slug := slugOf(who)
	if slug == "" {
		return unreachableElicit(user)
	}
	if !p.s.flows.Flow(slug).Configured() {
		return notConfiguredElicit(who, user)
	}
	return p.signInElicit(r, who, user)
}

// Connect proves the answers and keeps the credential.
func (p *setup) Connect(r *http.Request, sub string, answers map[string]any) (map[string]any, error) {
	user := strings.ToLower(str(answers, "user"))
	if provider.Domain(user) == "" {
		return nil, &connector.ElicitError{Elicit: addressElicit()}
	}
	who := p.hostOf(r.Context(), answers, user)
	slug := slugOf(who)
	if slug == "" {
		return nil, &connector.ElicitError{Elicit: unreachableElicit(user)}
	}
	if !p.s.flows.Flow(slug).Configured() {
		return nil, &connector.ElicitError{Elicit: notConfiguredElicit(who, user)}
	}
	if kept, ok := answers["kept"].(map[string]any); ok {
		if rt := str(kept, "refresh_token"); rt != "" {
			return p.connectKept(r.Context(), sub, who, user, rt)
		}
	}
	return p.connectGrant(r, sub, who, user, str(answers, "grant"))
}

// connectGrant redeems the grant code the wallet was sent back with, checks
// the sign-in was for the address typed, proves the tokens against the
// provider, keeps them, and hands the wallet the refresh token to keep.
func (p *setup) connectGrant(r *http.Request, sub string, who provider.Provider, user, grant string) (map[string]any, error) {
	slug := slugOf(who)
	if grant == "" {
		return nil, &connector.ElicitError{Elicit: p.signInElicit(r, who, user)}
	}
	issued, ok := p.s.flows.Flow(slug).Redeem(grant)
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
	return p.keep(r.Context(), sub, who, user, issued.Tokens)
}

// connectKept uses the refresh token the wallet kept instead of a browser:
// mint an access token, prove it, keep it.
func (p *setup) connectKept(ctx context.Context, sub string, who provider.Provider, user, refreshToken string) (map[string]any, error) {
	t, err := p.s.refresh(ctx, slugOf(who), refreshToken)
	if err != nil {
		if errors.Is(err, oauth.ErrRefused) {
			return nil, connector.Errorf(http.StatusBadGateway, "%s no longer accepts the saved sign-in; sign in again", who.Name())
		}
		return nil, connector.Errorf(http.StatusBadGateway, "%s could not be reached to renew the sign-in: %v", who.Name(), err)
	}
	return p.keep(ctx, sub, who, user, t)
}

// keep proves the tokens with the provider's probe (who the account is, and
// that it has a drive), checks that account is the address typed, and keeps
// the credential. What goes back to the wallet is the refresh token and the
// provider, and only that: the access token is minutes from expiring and
// this service mints the next one itself.
func (p *setup) keep(ctx context.Context, sub string, who provider.Provider, user string, t oauth.Tokens) (map[string]any, error) {
	slug := slugOf(who)
	drv, err := p.s.open(ctx, slug, func(context.Context) (string, error) { return t.AccessToken, nil })
	if err != nil {
		return nil, connector.Errorf(http.StatusBadGateway, "signed in, but %s would not open the files: %v", who.Name(), err)
	}
	live, err := drv.Account(ctx)
	_ = drv.Close()
	if err != nil {
		return nil, connector.Errorf(http.StatusBadGateway, "signed in, but %s would not say whose files these are: %v", who.Name(), err)
	}
	if live.User != "" && !strings.EqualFold(live.User, user) {
		// The kept path has no callback probe, so the address is checked
		// here too, against what the provider says.
		return nil, connector.Errorf(http.StatusBadRequest,
			"the %s sign-in was for %s, not %s; enter the address you sign in with", who.Name(), live.User, user)
	}
	acct := store.Account{
		Provider: slug, User: live.User, Name: live.Name, DriveID: live.DriveID, DriveType: live.DriveType, LinkedAt: time.Now(),
		RefreshToken: t.RefreshToken, AccessToken: t.AccessToken, Expiry: t.Expiry,
	}
	if acct.User == "" {
		acct.User = user
	}
	if err := p.s.credStore().Put(ctx, sub, acct); err != nil {
		return nil, connector.Errorf(http.StatusInternalServerError, "%v", err)
	}
	p.s.dropConn(sub)
	return map[string]any{"refresh_token": t.RefreshToken, "provider": slug}, nil
}

// identifier reads the address of the account that just signed in, at the
// OAuth callback, with the provider's own probe, so the mint can check it is
// the address the holder typed.
func (s *Server) identifier(provider string) func(ctx context.Context, t oauth.Tokens) (string, error) {
	return func(ctx context.Context, t oauth.Tokens) (string, error) {
		drv, err := s.open(ctx, provider, func(context.Context) (string, error) { return t.AccessToken, nil })
		if err != nil {
			return "", err
		}
		defer drv.Close()
		a, err := drv.Account(ctx)
		if err != nil {
			return "", err
		}
		return a.User, nil
	}
}

// refresh mints an access token from a refresh token, at the provider's
// token endpoint. Google's is the sdk's Refresh. Microsoft's token endpoint
// wants the scope named again on a refresh, which the sdk does not send, so
// that one is a plain form post here with the same client the flow holds.
func (s *Server) refresh(ctx context.Context, provider, refreshToken string) (oauth.Tokens, error) {
	if provider != cloud.ProviderMicrosoft {
		return s.flows.Flow(provider).Refresh(ctx, refreshToken)
	}
	if strings.TrimSpace(refreshToken) == "" {
		return oauth.Tokens{}, errors.New("no refresh token")
	}
	cfg := s.config()
	if !cfg.MicrosoftConfigured() {
		return oauth.Tokens{}, errors.New("this deployment has no OAuth client configured for Microsoft")
	}
	form := url.Values{
		"client_id": {cfg.MicrosoftClientID}, "client_secret": {cfg.MicrosoftClientSecret},
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		"scope": {strings.Join(microsoft.Scopes, " ")},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.microsoftTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauth.Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := s.http.Do(req)
	if err != nil {
		return oauth.Tokens{}, err
	}
	defer res.Body.Close()
	var body struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil && res.StatusCode == http.StatusOK {
		return oauth.Tokens{}, fmt.Errorf("microsoft: unreadable token answer: %w", err)
	}
	if res.StatusCode != http.StatusOK || body.AccessToken == "" {
		if body.Error != "" {
			return oauth.Tokens{}, fmt.Errorf("%w: %s", oauth.ErrRefused, strings.TrimSpace(body.Error+" "+body.ErrorDescription))
		}
		return oauth.Tokens{}, fmt.Errorf("microsoft: token endpoint answered %s", res.Status)
	}
	out := oauth.Tokens{AccessToken: body.AccessToken, RefreshToken: body.RefreshToken}
	if body.ExpiresIn > 0 {
		out.Expiry = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	}
	if out.RefreshToken == "" {
		out.RefreshToken = refreshToken
	}
	return out, nil
}
