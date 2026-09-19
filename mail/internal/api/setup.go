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
// It is kept in memory and nowhere else. The holder's device keeps the
// answers it sent and sends them again when this service asks again, so a
// restart here costs one more tap on their phone and nothing more.

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
)

// mailboxDetails is what the holder answered: the address and the password,
// and the server only when it could not be found from the address.
type mailboxDetails struct {
	Host       string
	User       string
	Password   string
	OwnDomains []string
}

// setupElicit is the question: address and password, the server found from
// the address (discover) and asked for only when nothing resolves.
func setupElicit() map[string]any {
	return map[string]any{
		"message": "Connect your mailbox. What you enter goes to the mail connector's enclave and is kept by this device; the service stores nothing.",
		"requestedSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user": map[string]any{"type": "string", "title": "Email address", "format": "email"},
				"password": map[string]any{"type": "string", "title": "App password", "format": "password",
					"description": "For Gmail: Google account > Security > App passwords. Never your sign-in password."},
			},
			"required": []string{"user", "password"},
		},
		"secrets": []string{"password"},
	}
}

// hostElicit is the follow-up question when the server could not be found.
func hostElicit(user string, tried []string) map[string]any {
	return map[string]any{
		"message": "The mail server for " + strings.TrimSpace(user) + " could not be found automatically.",
		"requestedSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host": map[string]any{"type": "string", "title": "IMAP server",
					"description": "As host:port, for example imap.example.com:993. Tried: " + strings.Join(tried, ", ") + "."},
			},
			"required": []string{"host"},
		},
	}
}

// connectFromSetup connects the mailbox from the wallet's answers, before a
// mint. It writes the response itself on every failure and reports whether
// the mint may go on: a 428 for a server that could not be found (the wallet
// asks one more question and mints again with all the answers), a 502 when
// the provider refused the details.
func (s *Server) connectFromSetup(w http.ResponseWriter, r *http.Request, cs store.Store, sub string, setup map[string]any) bool {
	str := func(k string) string {
		v, _ := setup[k].(string)
		return strings.TrimSpace(v)
	}
	req := mailboxDetails{User: str("user"), Password: str("password"), Host: str("host")}
	if req.User == "" || req.Password == "" {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"elicit": setupElicit()})
		return false
	}
	host, tried, err := s.pickHost(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return false
	}
	if host == "" {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"elicit": hostElicit(req.User, tried)})
		return false
	}
	req.Host = host
	if status, err := s.keepMailbox(r.Context(), cs, sub, req); err != nil {
		writeErr(w, status, err.Error())
		return false
	}
	return true
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
func (s *Server) keepMailbox(ctx context.Context, cs store.Store, sub string, req mailboxDetails) (int, error) {
	if err := cs.Put(ctx, sub, store.Account{
		Provider: "imap", Host: req.Host, User: req.User, Secret: req.Password,
		OwnDomains: cleanDomains(req.OwnDomains), LinkedAt: time.Now(),
	}); err != nil {
		return http.StatusInternalServerError, err
	}
	s.dropConn(sub) // any cached connection is for the old credential
	return http.StatusOK, nil
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
