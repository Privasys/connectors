// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

// Setup on the wallet's approval screen (plan §3.7, Bertrand 2026-09-16:
// "move all elicitation to the wallet when they request secrets").
//
// The holder connects their mailbox where their trust is visible: the
// wallet, on the same tap that approves an assistant's access. The wallet
// reads what this service needs (GET /v1/capabilities/setup), draws the
// schema, and sends the answers with the mint (POST /v1/capabilities,
// `setup`). The values make one attested hop, phone to this enclave; the
// assistant, its harness and the runtime never hold them. The conversation's
// connect_mailbox (link.go) asks for the same things through MCP elicitation
// and stays for a wallet without this screen.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Privasys/connectors/mail/internal/broker"
	"github.com/Privasys/connectors/mail/internal/store"
)

// setupNeeded reads a credential lookup as "the holder must connect": no
// account, no folder for one, a folder withdrawn since.
func setupNeeded(err error) bool {
	return errors.Is(err, store.ErrNoAccount) || errors.Is(err, store.ErrFolderWithdrawn) ||
		errors.Is(err, broker.ErrNotApproved) || errors.Is(err, broker.ErrDeclined)
}

// wantsSetup reports a caller that renders a 428 question (the wallet says
// so; an older wallet gets the 412 it knows). The header is set by the
// wallet on the mint it makes from an approval screen with the form.
func wantsSetup(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Privasys-Setup")), "form") ||
		strings.Contains(r.Header.Get("Accept"), "application/vnd.privasys.setup+json")
}

// setupElicit is the question: address and password, the server found from
// the address (discover) and asked for only when nothing resolves. The same
// schema connect_mailbox sends (link.go), kept in one place.
func setupElicit() map[string]any {
	return map[string]any{
		"message": "Connect your mailbox. What you enter goes to the mail connector's enclave and is sealed in your own Drive.",
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

// folderPrerequisites lists the approvals this service needs before it can
// keep anything for the holder: its own Drive folder, asked of the runtime
// now so the wallet can complete it first. `lookup` is what the credential
// read answered; a folder withdrawn in Drive is asked for again with retry.
func (s *Server) folderPrerequisites(ctx context.Context, cs store.Store, sub string, lookup error) []map[string]string {
	a, ok := cs.(store.Approver)
	if !ok {
		return []map[string]string{}
	}
	retry := errors.Is(lookup, store.ErrFolderWithdrawn)
	if !retry {
		approved, err := a.Approved(ctx, sub)
		if err != nil || approved {
			return []map[string]string{}
		}
	}
	ask, err := a.AskApproval(ctx, sub, retry)
	if err != nil || !ask.Pending() {
		return []map[string]string{}
	}
	return []map[string]string{{"app_host": ask.AppHost, "nonce": ask.Nonce}}
}

// connectFromSetup connects the mailbox from the wallet's answers, before a
// mint. It writes the response itself on every failure and reports whether
// the mint may go on: a 428 for a server that could not be found (the
// wallet asks one more question and mints again with all the answers), a
// 412 when this service still has no folder to seal into, a 502 when the
// provider refused the details.
func (s *Server) connectFromSetup(w http.ResponseWriter, r *http.Request, cs store.Store, sub string, setup map[string]any) bool {
	str := func(k string) string {
		v, _ := setup[k].(string)
		return strings.TrimSpace(v)
	}
	req := linkRequest{User: str("user"), Password: str("password"), Host: str("host")}
	if req.User == "" || req.Password == "" {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"elicit": setupElicit()})
		return false
	}
	if pending, err := s.ensureFolder(r.Context(), cs, sub); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return false
	} else if pending {
		writeErr(w, http.StatusPreconditionFailed, "the mail connector has no folder in this holder's Drive to keep the credential in; approve that folder first, then approve this again")
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
	if _, status, err := s.storeMailbox(r.Context(), cs, sub, req); err != nil {
		writeErr(w, status, err.Error())
		return false
	}
	return true
}
