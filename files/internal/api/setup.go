// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// Connecting an account happens in one place: the wallet's approval screen.
//
// The wallet asks which provider first, alone (428), because what comes next
// depends on it. The second step is one button for that provider: the wallet
// opens this service's /v1/oauth/start in an authentication session, the
// holder signs in with Microsoft or Google in their browser, and only a
// one-time grant code comes back to the wallet, which sends it with the
// mint. Nothing is ever typed but the provider choice, and optionally the
// address, which is only used to check that the sign-in was for the account
// the holder meant.
//
// A refresh token is the one thing this service asks the wallet to keep for
// it (`keep`), and a later mint carries it back as
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

	"github.com/Privasys/connectors/files/internal/cloud"
	"github.com/Privasys/connectors/files/internal/store"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/oauth"
)

type setup struct{ s *Server }

// The provider choice as the wallet shows it, and the slug it becomes.
var providerNames = map[string]string{"microsoft": cloud.ProviderMicrosoft, "google": cloud.ProviderGoogle}

func providerOf(answers map[string]any) string {
	v, _ := answers["provider"].(string)
	return providerNames[strings.ToLower(strings.TrimSpace(v))]
}

func str(answers map[string]any, k string) string {
	v, _ := answers[k].(string)
	return strings.TrimSpace(v)
}

// providerElicit is the first step: which provider, alone, so the second
// step can be drawn for it. The address is optional and nothing depends on
// it but a check that the sign-in matched.
func providerElicit() map[string]any {
	return connector.Elicit(
		"Connect your files. Choose where they are; you then sign in with that provider in your browser, and nothing is typed here. The service stores nothing: the sign-in is kept by this device.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider": map[string]any{
					"type": "string", "title": "Provider",
					"enum": []string{"Microsoft", "Google"}, "enumNames": []string{"Microsoft (OneDrive, SharePoint)", "Google Drive"},
				},
				"user": map[string]any{"type": "string", "title": "Account email (optional)", "format": "email"},
			},
			"required": []string{"provider"},
		})
}

// signInElicit is the second step: one button for the provider. The wallet
// draws it from x-privasys-oauth and fills `grant` with the code the sign-in
// sent back.
func (p *setup) signInElicit(r *http.Request, provider, user string) map[string]any {
	label := "Microsoft"
	if provider == cloud.ProviderGoogle {
		label = "Google"
	}
	props := map[string]any{
		"provider": map[string]any{"type": "string", "title": "Provider", "default": label, "enum": []string{label}},
		"grant":    p.s.flows.SchemaProperty(r, provider),
	}
	if user != "" {
		props["user"] = map[string]any{"type": "string", "title": "Account email", "format": "email", "default": user}
	}
	return connector.Elicit(
		"Sign in with "+label+" to connect your files; the sign-in happens in your browser and only a one-time code comes back to this device.",
		map[string]any{"type": "object", "properties": props, "required": []string{"provider", "grant"}})
}

// Question is the step the answers so far call for.
func (p *setup) Question(r *http.Request, answers map[string]any) map[string]any {
	provider := providerOf(answers)
	if provider == "" {
		return providerElicit()
	}
	return p.signInElicit(r, provider, str(answers, "user"))
}

// Connect proves the answers and keeps the credential.
func (p *setup) Connect(r *http.Request, sub string, answers map[string]any) (map[string]any, error) {
	provider := providerOf(answers)
	if provider == "" {
		return nil, &connector.ElicitError{Elicit: providerElicit()}
	}
	user := strings.ToLower(str(answers, "user"))
	if !p.s.flows.Flow(provider).Configured() {
		return nil, connector.Errorf(http.StatusServiceUnavailable,
			"this deployment has no %s OAuth client configured, so a %s account cannot be connected here", providerLabel(provider), providerLabel(provider))
	}
	if kept, ok := answers["kept"].(map[string]any); ok {
		if rt := str(kept, "refresh_token"); rt != "" {
			return p.connectKept(r.Context(), sub, provider, user, rt)
		}
	}
	return p.connectGrant(r, sub, provider, user, str(answers, "grant"))
}

func providerLabel(provider string) string {
	if provider == cloud.ProviderGoogle {
		return "Google"
	}
	return "Microsoft"
}

// connectGrant redeems the grant code the wallet was sent back with, proves
// the tokens against the provider, keeps them, and hands the wallet the
// refresh token to keep.
func (p *setup) connectGrant(r *http.Request, sub, provider, user, grant string) (map[string]any, error) {
	if grant == "" {
		return nil, &connector.ElicitError{Elicit: p.signInElicit(r, provider, user)}
	}
	issued, ok := p.s.flows.Flow(provider).Redeem(grant)
	if !ok {
		// Unknown, used or expired: one more sign-in, said plainly.
		q := p.signInElicit(r, provider, user)
		q["message"] = "The sign-in code is unknown, already used or expired. Sign in with " + providerLabel(provider) + " again."
		return nil, &connector.ElicitError{Elicit: q}
	}
	if user != "" && issued.Identity != "" && !strings.EqualFold(issued.Identity, user) {
		return nil, connector.Errorf(http.StatusBadRequest,
			"the %s sign-in was for %s, not %s; sign in with the account you meant", providerLabel(provider), issued.Identity, user)
	}
	if issued.RefreshToken == "" {
		return nil, connector.Errorf(http.StatusBadGateway,
			"%s issued no refresh token for this sign-in, so the connection would not outlive an hour; remove this app from the account's connected apps and sign in again", providerLabel(provider))
	}
	return p.keep(r.Context(), sub, provider, issued.Tokens)
}

// connectKept uses the refresh token the wallet kept instead of a browser:
// mint an access token, prove it, keep it.
func (p *setup) connectKept(ctx context.Context, sub, provider, user, refreshToken string) (map[string]any, error) {
	t, err := p.s.refresh(ctx, provider, refreshToken)
	if err != nil {
		if errors.Is(err, oauth.ErrRefused) {
			return nil, connector.Errorf(http.StatusBadGateway, "%s no longer accepts the saved sign-in; sign in again", providerLabel(provider))
		}
		return nil, connector.Errorf(http.StatusBadGateway, "%s could not be reached to renew the sign-in: %v", providerLabel(provider), err)
	}
	return p.keep(ctx, sub, provider, t)
}

// keep proves the tokens with the provider's probe (who the account is, and
// that it has a drive) and keeps the credential. What goes back to the
// wallet is the refresh token, and only that: the access token is minutes
// from expiring and this service mints the next one itself.
func (p *setup) keep(ctx context.Context, sub, provider string, t oauth.Tokens) (map[string]any, error) {
	drv, err := p.s.open(ctx, provider, func(context.Context) (string, error) { return t.AccessToken, nil })
	if err != nil {
		return nil, connector.Errorf(http.StatusBadGateway, "signed in, but %s would not open the files: %v", providerLabel(provider), err)
	}
	live, err := drv.Account(ctx)
	_ = drv.Close()
	if err != nil {
		return nil, connector.Errorf(http.StatusBadGateway, "signed in, but %s would not say whose files these are: %v", providerLabel(provider), err)
	}
	acct := store.Account{
		Provider: provider, User: live.User, Name: live.Name, DriveID: live.DriveID, DriveType: live.DriveType, LinkedAt: time.Now(),
		RefreshToken: t.RefreshToken, AccessToken: t.AccessToken, Expiry: t.Expiry,
	}
	if err := p.s.credStore().Put(ctx, sub, acct); err != nil {
		return nil, connector.Errorf(http.StatusInternalServerError, "%v", err)
	}
	p.s.dropConn(sub)
	return map[string]any{"refresh_token": t.RefreshToken}, nil
}

// identifier reads the address of the account that just signed in, at the
// OAuth callback, with the provider's own probe, so the mint can check it is
// the account the holder meant.
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
