// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// Connecting an account happens in one place: the wallet's approval screen.
//
// Two steps. The wallet asks which provider first, alone (428), because the
// sign-in button depends on it. The second step is that one button: the
// wallet opens this service's /v1/oauth/start in an authentication session,
// the holder signs in at Zoom or at Microsoft in their browser, and only a
// one-time grant code comes back to the wallet, which sends it with the
// mint. This service redeems the code, proves the tokens with one call to
// the provider, keeps them in memory, and hands the wallet the refresh
// token to keep for it.
//
// A refresh token is the one thing this service asks the wallet to keep
// (`keep`): the holder never typed it. A later mint carries it back as
// `setup.kept.refresh_token`, so nobody has to sign in again after a
// restart. Zoom rotates the refresh token at every renewal, so what the
// wallet keeps is the token from the last mint; every mint therefore
// answers with the CURRENT one, and a mint for an account already in memory
// does not touch the provider at all.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/connectors/meetings/internal/meet"
	"github.com/Privasys/connectors/meetings/internal/store"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/oauth"
)

type setup struct{ s *Server }

// The provider names the holder chooses between, and the slugs they map to.
const (
	choiceZoom  = "Zoom"
	choiceTeams = "Microsoft Teams"
)

var choices = []string{choiceZoom, choiceTeams}

func slugOf(choice string) string {
	switch strings.TrimSpace(choice) {
	case choiceZoom:
		return meet.ProviderZoom
	case choiceTeams:
		return meet.ProviderTeams
	}
	return ""
}

func choiceOf(slug string) string {
	switch slug {
	case meet.ProviderZoom:
		return choiceZoom
	case meet.ProviderTeams:
		return choiceTeams
	}
	return ""
}

// providerElicit is the first step: which platform holds the meetings.
func providerElicit() map[string]any {
	return connector.Elicit(
		"Connect your meeting transcripts. Choose where your meetings are held; you will then sign in there in your browser. "+
			"This service reads the transcripts the platform produced for meetings you were in, from your own account. It never joins a meeting and never records one.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider": map[string]any{"type": "string", "title": "Where your meetings are", "enum": choices},
			},
			"required": []string{"provider"},
		})
}

// signInElicit is the second step: one button for the chosen provider. The
// wallet draws it from x-privasys-oauth and fills `grant` with the code the
// sign-in sent back.
func (p *setup) signInElicit(r *http.Request, slug string) map[string]any {
	name := "Microsoft"
	if slug == meet.ProviderZoom {
		name = "Zoom"
	}
	return connector.Elicit(
		"Sign in with "+name+" to connect your meeting transcripts. The sign-in happens in your browser and only a one-time code comes back to this device; "+
			"the sign-in itself stays on your device and in this service's memory, never on its disk.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider": map[string]any{"type": "string", "title": "Where your meetings are", "enum": choices, "default": choiceOf(slug)},
				"grant":    p.s.flows.SchemaProperty(r, slug),
			},
			"required": []string{"provider", "grant"},
		})
}

func str(answers map[string]any, k string) string {
	v, _ := answers[k].(string)
	return strings.TrimSpace(v)
}

// Question is the step the answers so far call for.
func (p *setup) Question(r *http.Request, answers map[string]any) map[string]any {
	slug := slugOf(str(answers, "provider"))
	if slug == "" {
		return providerElicit()
	}
	return p.signInElicit(r, slug)
}

// Connect proves the answers and keeps the credential.
func (p *setup) Connect(r *http.Request, sub string, answers map[string]any) (map[string]any, error) {
	ctx := r.Context()
	slug := slugOf(str(answers, "provider"))
	if slug == "" {
		return nil, &connector.ElicitError{Elicit: providerElicit()}
	}
	flow := p.s.flows.Flow(slug)
	if flow == nil || !flow.Configured() {
		return nil, connector.Errorf(http.StatusServiceUnavailable,
			"this deployment has no OAuth client configured for %s, so a %s account cannot be connected here", choiceOf(slug), choiceOf(slug))
	}

	// An account already in memory for this provider is proven and current:
	// a mint for a second app, or a wallet re-sending what it kept, must not
	// spend a refresh at the provider, and the wallet gets the token that is
	// current now.
	if acct, err := p.s.credStore().Get(ctx, sub); err == nil && acct.Provider == slug && acct.RefreshToken != "" {
		return map[string]any{"refresh_token": acct.RefreshToken}, nil
	}

	if kept, ok := answers["kept"].(map[string]any); ok {
		if rt := str(kept, "refresh_token"); rt != "" {
			return p.connectKept(ctx, sub, slug, flow, rt)
		}
	}
	return p.connectGrant(r, sub, slug, flow, str(answers, "grant"))
}

// connectGrant redeems the grant code the wallet was sent back with, proves
// the tokens against the provider, keeps them, and hands the wallet the
// refresh token to keep.
func (p *setup) connectGrant(r *http.Request, sub, slug string, flow *oauth.Flow, grant string) (map[string]any, error) {
	if grant == "" {
		return nil, &connector.ElicitError{Elicit: p.signInElicit(r, slug)}
	}
	issued, ok := flow.Redeem(grant)
	if !ok {
		// Unknown, used or expired: one more sign-in, said plainly.
		q := p.signInElicit(r, slug)
		q["message"] = "The sign-in code is unknown, already used or expired. Sign in with " + choiceOf(slug) + " again."
		return nil, &connector.ElicitError{Elicit: q}
	}
	if issued.RefreshToken == "" {
		return nil, connector.Errorf(http.StatusBadGateway,
			"%s issued no refresh token for this sign-in, so the connection would not outlive an hour; remove this app from the account's connected apps and sign in again", choiceOf(slug))
	}
	return p.keep(r.Context(), sub, slug, issued.Tokens)
}

// connectKept uses the refresh token the wallet kept instead of a browser:
// mint an access token, prove it, keep it.
func (p *setup) connectKept(ctx context.Context, sub, slug string, flow *oauth.Flow, refreshToken string) (map[string]any, error) {
	t, err := flow.Refresh(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, oauth.ErrRefused) {
			return nil, connector.Errorf(http.StatusBadGateway, "%s no longer accepts the saved sign-in; sign in again", choiceOf(slug))
		}
		return nil, connector.Errorf(http.StatusBadGateway, "%s could not be reached to renew the sign-in: %v", choiceOf(slug), err)
	}
	return p.keep(ctx, sub, slug, t)
}

// keep proves the tokens with one call to the provider and keeps the
// credential. What goes back to the wallet is the refresh token, and only
// that: the access token is minutes from expiring and this service mints
// the next one itself.
func (p *setup) keep(ctx context.Context, sub, slug string, t oauth.Tokens) (map[string]any, error) {
	drv, profile, err := p.s.open(ctx, slug, func(context.Context) (string, error) { return t.AccessToken, nil })
	if err != nil {
		if errors.Is(err, meet.ErrLogin) {
			return nil, connector.Errorf(http.StatusBadGateway, "signed in, but %s would not open the account with these tokens", choiceOf(slug))
		}
		return nil, connector.Errorf(http.StatusBadGateway, "signed in, but %s could not be reached to prove it: %v", choiceOf(slug), err)
	}
	_ = drv.Close()
	acct := store.Account{
		Provider: slug, User: profile.Address, Name: profile.Name, LinkedAt: time.Now(),
		RefreshToken: t.RefreshToken, AccessToken: t.AccessToken, Expiry: t.Expiry,
	}
	if err := p.s.credStore().Put(ctx, sub, acct); err != nil {
		return nil, connector.Errorf(http.StatusInternalServerError, "%v", err)
	}
	p.s.dropConn(sub)
	return map[string]any{"refresh_token": t.RefreshToken}, nil
}

// identifier is the probe run at the OAuth callback: it names the account
// that signed in, by one call to the provider, so a sign-in that cannot be
// opened is refused before the wallet is handed a grant code.
func (s *Server) identifier(slug string) func(ctx context.Context, t oauth.Tokens) (string, error) {
	return func(ctx context.Context, t oauth.Tokens) (string, error) {
		drv, profile, err := s.open(ctx, slug, func(context.Context) (string, error) { return t.AccessToken, nil })
		if err != nil {
			return "", err
		}
		_ = drv.Close()
		return profile.Address, nil
	}
}
