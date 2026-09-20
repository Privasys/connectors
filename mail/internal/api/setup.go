// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// Connecting a mailbox happens in one place: the wallet's approval screen.
//
// The holder types their address and an app password where their trust is
// visible, on the same tap that approves an assistant's access. The wallet
// reads what this service needs (GET /v1/capabilities/setup), draws the
// schema, and sends the answers with the mint (POST /v1/capabilities,
// `setup`). The values make one attested hop, phone to this enclave; the
// assistant, its harness and the runtime never hold them.
//
// That is also the only moment a credential crosses into this service. Two
// rules make it safe rather than merely brief. The credential is PROVED
// before it is kept, because a credential that does not work is a support
// problem the holder will blame on the agent. And it is never echoed back, in
// any form, by any endpoint: the only thing that reads it after this is the
// code that dials the mailbox.
//
// The routes, the mint and the 428 contract are the sdk's. What is this
// connector's is below: the schema, the probe, and what is kept.

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
)

// mailboxDetails is what the holder answered: the address and the password,
// and the server only when it could not be found from the address.
type mailboxDetails struct {
	Host       string
	User       string
	Password   string
	OwnDomains []string
}

// setup is the connector's side of the wallet's approval screen.
type setup struct{ s *Server }

// setupElicit is the question: address and password, the server found from
// the address (discover) and asked for only when nothing resolves.
func setupElicit() map[string]any {
	return connector.Elicit(
		"Connect your mailbox. What you enter goes to the mail connector's enclave and is kept by this device; the service stores nothing.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user": map[string]any{"type": "string", "title": "Email address", "format": "email"},
				"password": map[string]any{"type": "string", "title": "App password", "format": "password",
					"description": "For Gmail: Google account > Security > App passwords. Never your sign-in password."},
			},
			"required": []string{"user", "password"},
		},
		"password")
}

// hostElicit is the follow-up question when the server could not be found.
func hostElicit(user string, tried []string) map[string]any {
	return connector.Elicit(
		"The mail server for "+strings.TrimSpace(user)+" could not be found automatically.",
		map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host": map[string]any{"type": "string", "title": "IMAP server",
					"description": "As host:port, for example imap.example.com:993. Tried: " + strings.Join(tried, ", ") + "."},
			},
			"required": []string{"host"},
		})
}

// Question is the same at every step: the wallet accumulates answers, and
// the follow-up for a server nobody could find comes from Connect.
func (*setup) Question(context.Context, map[string]any) map[string]any { return setupElicit() }

// Connect connects the mailbox from the wallet's answers, before a mint: a
// 428 for a server that could not be found (the wallet asks one more question
// and mints again with all the answers), a 502 when the provider refused the
// details. There is nothing for the wallet to keep: an IMAP credential is
// what the holder typed, which their device already keeps.
func (p *setup) Connect(ctx context.Context, sub string, answers map[string]any) (map[string]any, error) {
	str := func(k string) string {
		v, _ := answers[k].(string)
		return strings.TrimSpace(v)
	}
	req := mailboxDetails{User: str("user"), Password: str("password"), Host: str("host")}
	if req.User == "" || req.Password == "" {
		return nil, &connector.ElicitError{Elicit: setupElicit()}
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
	if err := s.credStore().Put(ctx, sub, store.Account{
		Provider: "imap", Host: req.Host, User: req.User, Secret: req.Password,
		OwnDomains: cleanDomains(req.OwnDomains), LinkedAt: time.Now(),
	}); err != nil {
		return err
	}
	s.dropConn(sub) // any cached connection is for the old credential
	return nil
}

// proveCredential opens the mailbox once and closes it.
//
// It goes through s.prove so a test can stand in for the mailbox; the real
// one dials it.
func (s *Server) proveCredential(ctx context.Context, req mailboxDetails) error {
	if s.prove != nil {
		return s.prove(ctx, req)
	}
	return dialAndList(ctx, req)
}

func dialAndList(ctx context.Context, req mailboxDetails) error {
	drv, err := imapdrv.Open(imapdrv.Config{Host: req.Host, User: req.User, Password: req.Password})
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
