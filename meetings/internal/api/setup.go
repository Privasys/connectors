// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// Connecting an account happens in one place: the wallet's approval screen.
//
// The wallet asks for the address first, alone (428), because the address
// decides what comes next. A Microsoft address (Microsoft's own domains, or
// a domain whose MX is Microsoft 365) may hold its meetings on Teams or on
// Zoom, so it gets one choice between the two, then the sign-in button for
// the one chosen; any other address gets Continue with Zoom directly,
// because a Zoom account sits on any address and Teams needs a Microsoft
// one. A choice is only ever drawn among the providers this deployment has
// a client for, and a provider with none is said plainly, with nothing to
// fill.
//
// The wallet opens this service's /v1/oauth/start in an authentication
// session, the holder signs in at Zoom or at Microsoft in their browser,
// and only a one-time grant code comes back to the wallet, which sends it
// with the mint. This service redeems the code, proves the tokens with one
// call to the provider, refuses a sign-in for any address but the one
// typed, keeps the tokens in memory, and hands the wallet the refresh
// token to keep for it.
//
// A refresh token is the one thing this service asks the wallet to keep
// (`keep`), with the provider it is for: the holder never typed it. A
// later mint carries both back as `setup.kept`, so nobody has to sign in
// again after a restart. Zoom rotates the refresh token at every renewal,
// so what the wallet keeps is the token from the last mint; every mint
// therefore answers with the CURRENT one, and a mint for an account already
// in memory does not touch the provider at all.

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
	"github.com/Privasys/connectors/sdk/provider"
)

type setup struct{ s *Server }

// The provider names the holder may choose between, and the slugs they
// map to.
const (
	choiceZoom  = "Zoom"
	choiceTeams = "Microsoft Teams"
)

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

// signInName is what the button says: the sign-in is at Microsoft, not at
// Teams.
func signInName(slug string) string {
	if slug == meet.ProviderTeams {
		return "Microsoft"
	}
	return "Zoom"
}

func str(answers map[string]any, k string) string {
	v, _ := answers[k].(string)
	return strings.TrimSpace(v)
}

// addressElicit is the first step: the address alone, so the second step
// can be drawn for it.
func addressElicit() map[string]any {
	return connector.Elicit(
		"Connect your meeting transcripts. Enter the email address of the account your meetings are held on; the connector finds who hosts it and asks you to sign in at Zoom or at Microsoft in your browser. "+
			"This service reads the transcripts the platform produced for meetings you were in, from your own account. It never joins a meeting and never records one.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user": map[string]any{"type": "string", "title": "Email address", "format": "email"},
			},
			"required": []string{"user"},
		})
}

// choiceElicit is the second step for a Microsoft address with both
// providers open to it: Teams or Zoom, because a Microsoft 365 user may
// hold their meetings on either.
func choiceElicit(user string, choices []string) map[string]any {
	return connector.Elicit(
		user+" is a Microsoft account. Its meetings may be on Microsoft Teams or on Zoom: choose where they are held, and you will then sign in there in your browser.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user":     map[string]any{"type": "string", "title": "Email address", "format": "email", "default": user},
				"provider": map[string]any{"type": "string", "title": "Where your meetings are", "enum": choices},
			},
			"required": []string{"user", "provider"},
		})
}

// signInElicit is the last step: one button for the provider. The wallet
// draws it from x-privasys-oauth and fills `grant` with the code the
// sign-in sent back.
func (p *setup) signInElicit(r *http.Request, slug, user string) map[string]any {
	return connector.Elicit(
		"Sign in with "+signInName(slug)+" to connect the meeting transcripts of "+user+". The sign-in happens in your browser and only a one-time code comes back to this device; "+
			"the sign-in itself stays on your device and in this service's memory, never on its disk.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user":     map[string]any{"type": "string", "title": "Email address", "format": "email", "default": user},
				"provider": map[string]any{"type": "string", "title": "Where your meetings are", "enum": []string{choiceOf(slug)}, "default": choiceOf(slug)},
				"grant":    p.s.flows.SchemaProperty(r, slug),
			},
			"required": []string{"user", "provider", "grant"},
		})
}

// notConfiguredElicit is the honest answer when no provider open to this
// address has a client on this deployment: a sentence, and nothing to fill.
func notConfiguredElicit(user string, open []string) map[string]any {
	names := make([]string, 0, len(open))
	for _, slug := range open {
		names = append(names, choiceOf(slug))
	}
	return connector.Elicit(
		"This deployment of the meetings connector has no sign-in configured for "+strings.Join(names, " or ")+", so it cannot connect the meetings of "+user+". Ask whoever runs it to configure one.",
		map[string]any{"type": "object", "properties": map[string]any{}})
}

// openTo lists the providers an address may hold its meetings on, in the
// order a choice shows them: Teams and Zoom for a Microsoft address, Zoom
// alone for any other. A kept sign-in names its provider (`kept.provider`),
// and that word wins: the sign-in already proved it, and a resolver that
// cannot be reached at that moment must not turn a kept Teams token into
// a Zoom question.
func (p *setup) openTo(ctx context.Context, answers map[string]any, user string) []string {
	if kept, ok := answers["kept"].(map[string]any); ok {
		switch slug := str(kept, "provider"); slug {
		case meet.ProviderZoom, meet.ProviderTeams:
			return []string{slug}
		}
	}
	if p.s.who.Of(ctx, user) == provider.Microsoft {
		return []string{meet.ProviderTeams, meet.ProviderZoom}
	}
	return []string{meet.ProviderZoom}
}

// configured keeps the providers this deployment has a client for.
func (p *setup) configured(slugs []string) []string {
	var out []string
	for _, slug := range slugs {
		if f := p.s.flows.Flow(slug); f != nil && f.Configured() {
			out = append(out, slug)
		}
	}
	return out
}

// step works out where the answers so far have got to: the provider that
// is settled, or the question that settles it.
func (p *setup) step(r *http.Request, answers map[string]any) (user, slug string, ask map[string]any) {
	user = strings.ToLower(str(answers, "user"))
	if provider.Domain(user) == "" {
		return "", "", addressElicit()
	}
	open := p.openTo(r.Context(), answers, user)
	able := p.configured(open)
	if len(able) == 0 {
		return user, "", notConfiguredElicit(user, open)
	}
	if chosen := slugOf(str(answers, "provider")); chosen != "" {
		for _, s := range able {
			if s == chosen {
				return user, chosen, nil
			}
		}
	}
	if len(able) == 1 {
		return user, able[0], nil
	}
	choices := make([]string, 0, len(able))
	for _, s := range able {
		choices = append(choices, choiceOf(s))
	}
	return user, "", choiceElicit(user, choices)
}

// Question is the step the answers so far call for.
func (p *setup) Question(r *http.Request, answers map[string]any) map[string]any {
	user, slug, ask := p.step(r, answers)
	if ask != nil {
		return ask
	}
	return p.signInElicit(r, slug, user)
}

// Connect proves the answers and keeps the credential.
func (p *setup) Connect(r *http.Request, sub string, answers map[string]any) (map[string]any, error) {
	ctx := r.Context()
	user, slug, ask := p.step(r, answers)
	if ask != nil {
		return nil, &connector.ElicitError{Elicit: ask}
	}
	flow := p.s.flows.Flow(slug)

	// An account already in memory for this provider and this address is
	// proven and current: a mint for a second app, or a wallet re-sending
	// what it kept, must not spend a refresh at the provider, and the
	// wallet gets the token that is current now.
	if acct, err := p.s.credStore().Get(ctx, sub); err == nil && acct.Provider == slug && acct.RefreshToken != "" && strings.EqualFold(acct.User, user) {
		return map[string]any{"refresh_token": acct.RefreshToken, "provider": slug}, nil
	}

	if kept, ok := answers["kept"].(map[string]any); ok {
		if rt := str(kept, "refresh_token"); rt != "" {
			return p.connectKept(ctx, sub, slug, user, flow, rt)
		}
	}
	return p.connectGrant(r, sub, slug, user, flow, str(answers, "grant"))
}

// connectGrant redeems the grant code the wallet was sent back with, checks
// the sign-in was for the address typed, proves the tokens against the
// provider, keeps them, and hands the wallet the refresh token to keep.
func (p *setup) connectGrant(r *http.Request, sub, slug, user string, flow *oauth.Flow, grant string) (map[string]any, error) {
	if grant == "" {
		return nil, &connector.ElicitError{Elicit: p.signInElicit(r, slug, user)}
	}
	issued, ok := flow.Redeem(grant)
	if !ok {
		// Unknown, used or expired: one more sign-in, said plainly.
		q := p.signInElicit(r, slug, user)
		q["message"] = "The sign-in code is unknown, already used or expired. Sign in with " + signInName(slug) + " again."
		return nil, &connector.ElicitError{Elicit: q}
	}
	if issued.Identity != "" && !strings.EqualFold(issued.Identity, user) {
		return nil, connector.Errorf(http.StatusBadRequest,
			"the %s sign-in was for %s, not %s; enter the address you sign in with", signInName(slug), issued.Identity, user)
	}
	if issued.RefreshToken == "" {
		return nil, connector.Errorf(http.StatusBadGateway,
			"%s issued no refresh token for this sign-in, so the connection would not outlive an hour; remove this app from the account's connected apps and sign in again", choiceOf(slug))
	}
	return p.keep(r.Context(), sub, slug, user, issued.Tokens)
}

// connectKept uses the refresh token the wallet kept instead of a browser:
// mint an access token, prove it, keep it.
func (p *setup) connectKept(ctx context.Context, sub, slug, user string, flow *oauth.Flow, refreshToken string) (map[string]any, error) {
	t, err := flow.Refresh(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, oauth.ErrRefused) {
			return nil, connector.Errorf(http.StatusBadGateway, "%s no longer accepts the saved sign-in; sign in again", choiceOf(slug))
		}
		return nil, connector.Errorf(http.StatusBadGateway, "%s could not be reached to renew the sign-in: %v", choiceOf(slug), err)
	}
	return p.keep(ctx, sub, slug, user, t)
}

// keep proves the tokens with one call to the provider, checks the account
// is the address typed, and keeps the credential. What goes back to the
// wallet is the refresh token and the provider, and only that: the access
// token is minutes from expiring and this service mints the next one
// itself.
func (p *setup) keep(ctx context.Context, sub, slug, user string, t oauth.Tokens) (map[string]any, error) {
	drv, profile, err := p.s.open(ctx, slug, func(context.Context) (string, error) { return t.AccessToken, nil })
	if err != nil {
		if errors.Is(err, meet.ErrLogin) {
			return nil, connector.Errorf(http.StatusBadGateway, "signed in, but %s would not open the account with these tokens", choiceOf(slug))
		}
		return nil, connector.Errorf(http.StatusBadGateway, "signed in, but %s could not be reached to prove it: %v", choiceOf(slug), err)
	}
	_ = drv.Close()
	if profile.Address != "" && !strings.EqualFold(profile.Address, user) {
		// The kept path has no callback probe, so the address is checked
		// here too, against what the provider says.
		return nil, connector.Errorf(http.StatusBadRequest,
			"the %s sign-in was for %s, not %s; enter the address you sign in with", signInName(slug), profile.Address, user)
	}
	acct := store.Account{
		Provider: slug, User: profile.Address, Name: profile.Name, LinkedAt: time.Now(),
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

// identifier is the probe run at the OAuth callback: it names the account
// that signed in, by one call to the provider (Graph's /me, Zoom's
// /users/me), so a sign-in that cannot be opened is refused before the
// wallet is handed a grant code, and the mint can check the address.
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
