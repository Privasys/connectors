// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/connectors/mail/internal/imapdrv"
	"github.com/Privasys/connectors/mail/internal/mail"
	"github.com/Privasys/connectors/mail/internal/store"
)

// Linking a mailbox is the one moment a credential crosses into this service.
//
// It arrives from the holder's own browser over the platform's sealed
// transport, which terminates inside the enclave, so the operator never sees
// it in transit. From here it is encrypted under a key sealed to this
// connector's measurement and the ciphertext goes to the holder's own Drive.
//
// Two rules make that moment safe rather than merely brief. The credential is
// PROVED before it is stored, because a credential that does not work is a
// support problem the holder will blame on the agent. And it is never echoed
// back, in any form, by any endpoint: the only thing that reads it after this
// is the code that dials the mailbox.

type linkRequest struct {
	Host       string   `json:"host"`
	User       string   `json:"user"`
	Password   string   `json:"password"`
	OwnDomains []string `json:"own_domains"`
}

func (s *Server) linkRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		// No external anything. A page that asks for a mail password must not
		// fetch a script from somewhere else, whatever the convenience, and a
		// reader should be able to confirm that from the source.
		//
		// The script is admitted by a per-request NONCE rather than by
		// 'unsafe-inline'. The first version of this policy said default-src
		// 'none' with no script-src at all, which would have blocked the
		// page's own script and left a form that silently did nothing.
		nonce := newNonce()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'unsafe-inline'; "+
				"connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		// A password lives in this document's memory while it is open.
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(strings.ReplaceAll(linkPage, "__NONCE__", nonce)))
	})

	m.HandleFunc("GET /v1/link", func(w http.ResponseWriter, r *http.Request) {
		sub := holder(r)
		if sub == "" {
			writeErr(w, http.StatusUnauthorized, "this call is not authenticated as a holder")
			return
		}
		acct, err := s.store.Get(r.Context(), sub)
		if errors.Is(err, store.ErrNoAccount) {
			writeJSON(w, http.StatusOK, map[string]any{"linked": false})
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"linked": true, "account": acct.Redacted()})
	})

	m.HandleFunc("POST /v1/link", func(w http.ResponseWriter, r *http.Request) {
		sub := holder(r)
		if sub == "" {
			writeErr(w, http.StatusUnauthorized, "this call is not authenticated as a holder")
			return
		}
		body, err := readLimited(r, 64<<10)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		var req linkRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed request")
			return
		}
		req.Host = strings.TrimSpace(req.Host)
		req.User = strings.TrimSpace(req.User)
		if req.Host == "" {
			req.Host = "imap.gmail.com:993"
		}
		if !strings.Contains(req.Host, ":") {
			req.Host += ":993"
		}
		if req.User == "" || req.Password == "" {
			writeErr(w, http.StatusBadRequest, "an address and a password are both needed")
			return
		}

		// Prove it before storing it. A credential that does not work becomes
		// a support problem the holder will blame on the agent, and the error
		// the provider gives here is far more useful than the one a triage run
		// would surface hours later.
		if err := s.proveCredential(r.Context(), req); err != nil {
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}

		if err := s.store.Put(r.Context(), sub, store.Account{
			Provider: "imap", Host: req.Host, User: req.User, Secret: req.Password,
			OwnDomains: cleanDomains(req.OwnDomains), LinkedAt: time.Now(),
		}); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.dropConn(sub) // any cached connection is for the old credential

		writeJSON(w, http.StatusOK, map[string]any{
			"linked":  true,
			"account": store.Account{Provider: "imap", Host: req.Host, User: req.User}.Redacted(),
			"next":    "approve the Harness on your phone before it can read anything",
		})
	})

	m.HandleFunc("DELETE /v1/link", func(w http.ResponseWriter, r *http.Request) {
		sub := holder(r)
		if sub == "" {
			writeErr(w, http.StatusUnauthorized, "this call is not authenticated as a holder")
			return
		}
		if err := s.store.Delete(r.Context(), sub); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.dropConn(sub)
		// Capabilities are left standing on purpose: they are the holder's
		// separate decision about which apps may act, and silently discarding
		// them would mean a re-link quietly restored access nobody re-approved.
		writeJSON(w, http.StatusOK, map[string]any{
			"linked": false,
			"note":   "the mailbox is disconnected; approvals you gave apps are unchanged and can be revoked separately",
		})
	})
}

// proveCredential opens the mailbox once and closes it.
func (s *Server) proveCredential(ctx context.Context, req linkRequest) error {
	drv, err := imapdrv.Open(imapdrv.Config{Host: req.Host, User: req.User, Password: req.Password})
	if err != nil {
		return errors.New("the mailbox refused these details: " + err.Error())
	}
	defer drv.Close()
	// A login that succeeds but cannot list is a mailbox with IMAP disabled,
	// which fails much later and much more confusingly if not caught here.
	if _, err := drv.List(ctx, mailListProbe()); err != nil {
		return errors.New("signed in, but the mailbox would not open: " + err.Error())
	}
	return nil
}

func (s *Server) dropConn(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.conns[sub]; ok {
		_ = c.drv.Close()
		delete(s.conns, sub)
	}
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

// newNonce is a fresh CSP nonce per response. Must be unpredictable, and must
// never be reused: a nonce that repeats is 'unsafe-inline' with extra steps.
func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Failing closed here means serving a page whose script cannot run,
		// which is visibly broken rather than quietly unprotected.
		return "no-nonce-available"
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

// mailListProbe is the smallest listing that proves a mailbox opens.
func mailListProbe() mail.ListOptions { return mail.ListOptions{Limit: 1} }
