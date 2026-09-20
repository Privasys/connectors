// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// Connecting a mailbox happens in one place: the wallet's approval screen.
//
// The wallet asks for the address first, alone (428), because the address
// decides everything that follows: which server, which authorisation, and
// whether the mailbox can be connected here at all. For an address at Google
// or Microsoft (their own domains, or a domain whose MX is theirs) the second
// step is one button: the wallet opens this service's /v1/oauth/start in an
// authentication session, the holder signs in in their browser, and only a
// one-time grant code comes back to the wallet, which sends it with the
// mint. Both providers are retiring passwords over IMAP, so a holder whose
// address is at either is never offered a password field. For any other
// address the second step is an app password, proved against the server
// found from the address (discover), the server itself asked for only when
// nothing resolves.
//
// The wallet reads what this service needs (GET /v1/capabilities/setup),
// draws the step, and sends the answers with the mint (POST
// /v1/capabilities, `setup`). The values make one attested hop, phone to
// this enclave; the assistant, its harness and the runtime never hold them.
//
// That is also the only moment a credential crosses into this service. Two
// rules make it safe rather than merely brief. The credential is PROVED
// before it is kept (open the mailbox, list one message), because a
// credential that does not work is a support problem the holder will blame
// on the agent. And it is never echoed back, in any form, by any endpoint:
// the only thing that reads it after this is the code that dials the
// mailbox.
//
// A password is what the holder typed, and their device already keeps it.
// A refresh token is not: it is the one thing this service asks the wallet
// to keep for it (`keep`), and a later mint carries it back as
// `setup.kept.refresh_token` so nobody has to sign in again after a restart.
//
// The routes, the mint and the 428 contract are the sdk's. What is this
// connector's is below: the steps, the probe, and what is kept.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/connectors/mail/internal/discover"
	"github.com/Privasys/connectors/mail/internal/imapdrv"
	"github.com/Privasys/connectors/mail/internal/mail"
	"github.com/Privasys/connectors/mail/internal/store"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/provider"
)

// mailboxDetails is what the holder answered for a provider we reach
// directly: the address and the password, and the server only when it could
// not be found from the address.
type mailboxDetails struct {
	Host       string
	User       string
	Password   string
	OwnDomains []string
}

// setup is the connector's side of the wallet's approval screen.
type setup struct{ s *Server }

// addressElicit is the first step: the address alone, so the second step
// can be drawn for it.
func addressElicit() map[string]any {
	return connector.Elicit(
		"Connect your mailbox. Enter its email address; what you enter goes to the mail connector's enclave and is kept by this device, the service stores nothing.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user": map[string]any{"type": "string", "title": "Email address", "format": "email"},
			},
			"required": []string{"user"},
		})
}

// passwordElicit is the second step for a provider we reach directly.
func passwordElicit(user string) map[string]any {
	return connector.Elicit(
		"Enter an app password for "+user+". Never your sign-in password: your provider issues app passwords under its security settings.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user":     map[string]any{"type": "string", "title": "Email address", "format": "email", "default": user},
				"password": map[string]any{"type": "string", "title": "App password", "format": "password"},
			},
			"required": []string{"user", "password"},
		},
		"password")
}

// hostElicit is the follow-up question when the server could not be found.
func hostElicit(user string, tried []string) map[string]any {
	return connector.Elicit(
		"The mail server for "+user+" could not be found automatically.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host": map[string]any{"type": "string", "title": "IMAP server",
					"description": "As host:port, for example imap.example.com:993. Tried: " + strings.Join(tried, ", ") + "."},
			},
			"required": []string{"host"},
		})
}

// notOfferedElicit is the honest answer for an address at a provider this
// deployment has no sign-in client for: the mailbox cannot be connected here
// until the deployer adds one, and no password is offered instead, because
// Microsoft has none and Google's are on the way out. The address stays
// editable, in case it was the wrong one.
func notOfferedElicit(user string, p provider.Provider) map[string]any {
	return connector.Elicit(
		user+" is a "+p.Name()+" account, and this deployment has no "+p.Name()+" sign-in configured yet, so it cannot be connected here until the deployer adds one. "+
			p.Name()+" accounts connect by signing in; an app password is not offered for them.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user": map[string]any{"type": "string", "title": "Email address", "format": "email", "default": user},
			},
			"required": []string{"user"},
		})
}

func str(answers map[string]any, k string) string {
	v, _ := answers[k].(string)
	return strings.TrimSpace(v)
}

// Question is the step the answers so far call for.
func (p *setup) Question(r *http.Request, answers map[string]any) map[string]any {
	user := str(answers, "user")
	if user == "" || provider.Domain(user) == "" {
		return addressElicit()
	}
	switch who := p.s.who.Of(r.Context(), user); who {
	case provider.Google, provider.Microsoft:
		return p.signInStep(r, who, user)
	}
	return passwordElicit(user)
}

// Connect proves the answers and keeps the credential, before a mint: a 428
// for one more question (the wallet asks it and mints again with all the
// answers), a 502 when the provider refused the details.
func (p *setup) Connect(r *http.Request, sub string, answers map[string]any) (map[string]any, error) {
	user := str(answers, "user")
	if user == "" || provider.Domain(user) == "" {
		return nil, &connector.ElicitError{Elicit: addressElicit()}
	}
	switch who := p.s.who.Of(r.Context(), user); who {
	case provider.Google, provider.Microsoft:
		return p.connectSignIn(r, sub, who, user, answers)
	}
	return p.connectPassword(r.Context(), sub, mailboxDetails{User: user, Password: str(answers, "password"), Host: str(answers, "host")})
}

// ---------------------------------------------------------------- password

// connectPassword proves an app password against the server found from the
// address, or the one the holder named, and keeps it. There is nothing for
// the wallet to keep: the credential is what the holder typed, which their
// device already keeps.
func (p *setup) connectPassword(ctx context.Context, sub string, req mailboxDetails) (map[string]any, error) {
	if req.Password == "" {
		return nil, &connector.ElicitError{Elicit: passwordElicit(req.User)}
	}
	host, tried, err := p.s.pickHost(ctx, req)
	if err != nil {
		return nil, connector.Errorf(http.StatusBadGateway, "%v", err)
	}
	if host == "" {
		return nil, &connector.ElicitError{Elicit: hostElicit(req.User, tried)}
	}
	req.Host = host
	if err := p.s.keepMailbox(ctx, sub, req); err != nil {
		return nil, connector.Errorf(http.StatusInternalServerError, "%v", err)
	}
	return nil, nil
}

// pickHost finds the server that accepts the credential: the one given, or
// the address's candidates (discover) in order. An empty host with the list
// tried means none could be reached, and the holder must name it; an error
// means a server was reached and refused the details, which no other server
// would fix.
func (s *Server) pickHost(ctx context.Context, req mailboxDetails) (host string, tried []string, err error) {
	req.User = strings.TrimSpace(req.User)
	if h := strings.TrimSpace(req.Host); h != "" {
		if !strings.Contains(h, ":") {
			h += ":993"
		}
		req.Host = h
		return h, []string{h}, s.proveCredential(ctx, req)
	}
	for _, candidate := range discover.Default.Candidates(ctx, req.User) {
		tried = append(tried, candidate)
		attempt := req
		attempt.Host = candidate
		err := s.proveCredential(ctx, attempt)
		if err == nil {
			return candidate, tried, nil
		}
		if errors.Is(err, imapdrv.ErrLogin) {
			return "", tried, err // the server answered: the details are wrong, not the server
		}
	}
	return "", tried, nil
}

// keepMailbox holds, in memory, a credential already proven against req.Host.
func (s *Server) keepMailbox(ctx context.Context, sub string, req mailboxDetails) error {
	return s.keep(ctx, sub, store.Account{
		Provider: store.ProviderIMAP, Host: req.Host, User: req.User, Secret: req.Password,
		OwnDomains: cleanDomains(req.OwnDomains), LinkedAt: time.Now(),
	})
}

// keep holds a proven credential in memory and drops any connection opened
// with the previous one.
func (s *Server) keep(ctx context.Context, sub string, acct store.Account) error {
	if err := s.credStore().Put(ctx, sub, acct); err != nil {
		return err
	}
	s.dropConn(sub) // any cached connection is for the old credential
	return nil
}

// proveCredential opens the mailbox once with a password and closes it.
func (s *Server) proveCredential(ctx context.Context, req mailboxDetails) error {
	return s.dialAndList(ctx, imapdrv.Config{Host: req.Host, User: req.User, Password: req.Password})
}

// dialAndList is the probe every credential goes through before it is kept:
// open the mailbox, list one message, close it. It goes through s.open so a
// test can stand in for the mailbox.
func (s *Server) dialAndList(ctx context.Context, cfg imapdrv.Config) error {
	drv, err := s.open(ctx, cfg)
	if err != nil {
		return fmt.Errorf("the mailbox refused these details: %w", err)
	}
	defer drv.Close()
	// A login that succeeds but cannot list is a mailbox with IMAP disabled,
	// which fails much later and much more confusingly if not caught here.
	if _, err := drv.List(ctx, mail.ListOptions{Limit: 1}); err != nil {
		return errors.New("signed in, but the mailbox would not open: " + err.Error())
	}
	return nil
}

func cleanDomains(in []string) []string {
	var out []string
	for _, d := range in {
		// Trim the whitespace BEFORE the "@", or a leading space means the
		// prefix is not at position zero and survives into the domain.
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}
