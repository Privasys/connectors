// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// A mailbox at Google or at Microsoft is connected by a sign-in, not a
// password. The wallet holds the browser; this service runs the exchange
// (the sdk's oauth), keeps the token set in memory, and enters the mailbox
// over IMAP with the access token (XOAUTH2). The refresh token is the one
// thing the wallet keeps for this service, and the access token is minted
// from it here as it expires, so the mailbox stays reachable for as long as
// the holder's approval stands and not an hour longer than the last token.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Privasys/connectors/mail/internal/imapdrv"
	"github.com/Privasys/connectors/mail/internal/mail"
	"github.com/Privasys/connectors/mail/internal/store"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/oauth"
	"github.com/Privasys/connectors/sdk/provider"
)

// The two providers this connector signs in with. The sdk knows no provider
// by name; these values are the whole of what it is told.
var (
	google = oauth.Provider{
		Name:     "Google",
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
		// The whole mailbox over IMAP (the one scope Gmail's IMAP accepts),
		// and the address of the account that signed in, read from the ID
		// token so the sign-in can be matched to the address the holder
		// typed.
		Scopes: []string{"https://mail.google.com/", "openid", "email"},
		// A refresh token is issued only with both. Without one the
		// credential would not outlive its first access token.
		AuthParams: map[string]string{"access_type": "offline", "prompt": "consent"},
	}
	microsoft = oauth.Provider{
		Name: "Microsoft",
		// The common tenant, so a work account and a personal account both
		// sign in through one registration.
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		// offline_access is what makes a refresh token come back; the IMAP
		// scope is the one resource this token is for. The address of the
		// account that signed in comes from the ID token (openid, email,
		// profile), NOT from a Graph call: Microsoft issues a token for one
		// resource per request, so a Graph scope beside the IMAP one would
		// be refused at the authorisation endpoint.
		Scopes: []string{"offline_access", "openid", "email", "profile", "https://outlook.office.com/IMAP.AccessAsUser.All"},
	}
)

// Where each provider's mailbox is entered. Fixed per provider: a signed-in
// mailbox is never discovered from the domain, because the token is only
// good at this one server.
const (
	googleIMAP    = "imap.gmail.com:993"
	microsoftIMAP = "outlook.office365.com:993"
)

func imapHost(who provider.Provider) string {
	if who == provider.Microsoft {
		return microsoftIMAP
	}
	return googleIMAP
}

// signInStep is the second step for an address at Google or Microsoft: one
// button, drawn by the wallet from x-privasys-oauth, which fills `grant`
// with the code the sign-in sent back. Without a client for the provider
// the step is the honest 428 instead, and nothing else is offered.
func (p *setup) signInStep(r *http.Request, who provider.Provider, user string) map[string]any {
	if !p.s.flows.Flow(string(who)).Configured() {
		return notOfferedElicit(user, who)
	}
	return connector.Elicit(
		user+" is a "+who.Name()+" account. Sign in with "+who.Name()+" to connect its mailbox; the sign-in happens in your browser and only a one-time code comes back to this device.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user":  map[string]any{"type": "string", "title": "Email address", "format": "email", "default": user},
				"grant": p.s.flows.SchemaProperty(r, string(who)),
			},
			"required": []string{"user", "grant"},
		})
}

// connectSignIn is the mint for such an address: with the token the wallet
// kept, no browser; with a grant code, the redeemed sign-in; with neither,
// the button.
func (p *setup) connectSignIn(r *http.Request, sub string, who provider.Provider, user string, answers map[string]any) (map[string]any, error) {
	ctx := r.Context()
	if !p.s.flows.Flow(string(who)).Configured() {
		return nil, &connector.ElicitError{Elicit: notOfferedElicit(user, who)}
	}
	if kept, ok := answers["kept"].(map[string]any); ok {
		if rt := str(kept, "refresh_token"); rt != "" {
			return p.connectKept(ctx, sub, who, user, rt)
		}
	}
	grant := str(answers, "grant")
	if grant == "" {
		return nil, &connector.ElicitError{Elicit: p.signInStep(r, who, user)}
	}
	issued, ok := p.s.flows.Flow(string(who)).Redeem(grant)
	if !ok {
		// Unknown, used or expired: one more sign-in, said plainly.
		q := p.signInStep(r, who, user)
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
	return p.keepTokens(ctx, sub, who, user, issued.Tokens)
}

// connectKept uses the refresh token the wallet kept instead of a browser:
// mint an access token, prove it, keep it. A token the provider refuses is
// a 502 with a sentence, and the wallet draws the button again.
func (p *setup) connectKept(ctx context.Context, sub string, who provider.Provider, user, refreshToken string) (map[string]any, error) {
	t, err := p.s.refresh(ctx, who, refreshToken)
	if err != nil {
		if errors.Is(err, oauth.ErrRefused) {
			return nil, connector.Errorf(http.StatusBadGateway, "%s no longer accepts the saved sign-in for %s; sign in again", who.Name(), user)
		}
		return nil, connector.Errorf(http.StatusBadGateway, "%s could not be reached to renew the sign-in: %v", who.Name(), err)
	}
	return p.keepTokens(ctx, sub, who, user, t)
}

// keepTokens proves the token set by opening the mailbox and listing one
// message, as a password is proved, and keeps it. What goes back to the
// wallet is the refresh token, and only that: the access token is minutes
// from expiring and this service mints the next one itself. It is the
// NEWEST refresh token that goes back, because Microsoft may hand a new one
// at every refresh and only the latest stays valid.
func (p *setup) keepTokens(ctx context.Context, sub string, who provider.Provider, user string, t oauth.Tokens) (map[string]any, error) {
	host := imapHost(who)
	err := p.s.dialAndList(ctx, imapdrv.Config{
		Host: host, User: user,
		Token: func(context.Context) (string, error) { return t.AccessToken, nil },
	})
	if err != nil {
		return nil, connector.Errorf(http.StatusBadGateway, "signed in, but %s's mailbox would not open for %s: %v", who.Name(), user, err)
	}
	if err := p.s.keep(ctx, sub, store.Account{
		Provider: string(who), Host: host, User: user, LinkedAt: time.Now(),
		RefreshToken: t.RefreshToken, AccessToken: t.AccessToken, Expiry: t.Expiry,
	}); err != nil {
		return nil, connector.Errorf(http.StatusInternalServerError, "%v", err)
	}
	return map[string]any{"refresh_token": t.RefreshToken}, nil
}

// identify reads the address of the account that just signed in, at the
// OAuth callback, so the mint can check it is the address the holder typed.
//
// It comes from the ID token rather than from a userinfo call, for both
// providers. Microsoft's access token is for the IMAP server alone and buys
// nothing at Graph, so there is no call to make; Google's would work, but
// one path is better than two. The token's signature is not checked, and
// need not be: it arrived in the token endpoint's own answer, over TLS, to
// a request carrying this deployment's client secret, which is the case
// OpenID Connect Core names (3.1.3.7, step 6) where TLS server validation
// stands in for the signature.
func (s *Server) identify(_ context.Context, t oauth.Tokens) (string, error) {
	return idTokenAddress(t.IDToken)
}

// idTokenAddress is the address a JWT names: `email`, else Microsoft's
// `preferred_username`, which is the account's sign-in name.
func idTokenAddress(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", errors.New("the sign-in carried no ID token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", fmt.Errorf("the ID token is malformed: %w", err)
	}
	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", fmt.Errorf("the ID token is malformed: %w", err)
	}
	addr := strings.ToLower(strings.TrimSpace(claims.Email))
	if addr == "" {
		addr = strings.ToLower(strings.TrimSpace(claims.PreferredUsername))
	}
	if !strings.Contains(addr, "@") {
		return "", errors.New("the ID token names no address")
	}
	return addr, nil
}

// errTokenRefused is the provider no longer honouring the kept sign-in.
var errTokenRefused = errors.New("the provider no longer accepts the saved sign-in for this mailbox; ask the user, then call request_access for their " +
	mail.Kind + " resource with ask_again true so they can sign in again on their device")

// tokenSource returns a bearer for the subject's mailbox, refreshing it
// from the kept refresh token when it is about to expire. The refreshed
// tokens go back into memory, the newest refresh token with them; the
// refresh token itself stays what the wallet keeps.
func (s *Server) tokenSource(sub string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		acct, err := s.credStore().Get(ctx, sub)
		if err != nil {
			return "", err
		}
		if acct.AccessToken != "" && time.Until(acct.Expiry) > time.Minute {
			return acct.AccessToken, nil
		}
		t, err := s.refresh(ctx, provider.Provider(acct.Provider), acct.RefreshToken)
		if err != nil {
			if errors.Is(err, oauth.ErrRefused) {
				return "", errTokenRefused
			}
			return "", err
		}
		acct.AccessToken, acct.Expiry = t.AccessToken, t.Expiry
		if t.RefreshToken != "" {
			acct.RefreshToken = t.RefreshToken
		}
		_ = s.credStore().Put(ctx, sub, acct)
		return t.AccessToken, nil
	}
}

// refresh mints an access token from a refresh token, at the provider's
// token endpoint. Google's is the sdk's Refresh. Microsoft's token endpoint
// wants the scope named again on a refresh, which the sdk does not send, so
// that one is a plain form post here with the same client the flow holds
// (the files connector learned this first).
func (s *Server) refresh(ctx context.Context, who provider.Provider, refreshToken string) (oauth.Tokens, error) {
	if who != provider.Microsoft {
		return s.flows.Flow(string(who)).Refresh(ctx, refreshToken)
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
