// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package api is the connector's HTTP surface: the tools an attested agent
// calls, and the platform endpoints the runtime calls.
//
// Two rules shape everything here.
//
// The acting user is asserted by the platform, never by the caller. It arrives
// as X-Privasys-On-Behalf-Of on a leg the runtime has already authenticated.
// An app that could name its own subject could read anyone's mailbox, so a
// request without one is refused rather than defaulted.
//
// The tool surface is the smallest thing that does the job. There is no send,
// no folder management and no arbitrary IMAP: every capability omitted is one
// a message cannot talk the model into using.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/connectors/mail/internal/grant"
	"github.com/Privasys/connectors/mail/internal/holder"
	"github.com/Privasys/connectors/mail/internal/imapdrv"
	"github.com/Privasys/connectors/mail/internal/mail"
	"github.com/Privasys/connectors/mail/internal/store"
)

// SubjectHeader is how the attested runtime names the acting user.
const SubjectHeader = "X-Privasys-On-Behalf-Of"

// idleTTL is how long an unused mailbox connection is kept. IMAP connections
// are cheap but not free, and a connector serving many users should not hold
// one open per user forever.
const idleTTL = 20 * time.Minute

type Server struct {
	store  store.Store
	grants grant.Store

	// requireGrant is the fail-closed switch. On the platform every tool call
	// must be covered by a capability the holder approved. It can be turned
	// off only for development, deliberately and explicitly, because a
	// connector that serves mail without checking is the whole risk.
	requireGrant bool

	// cfg is the configure-then-freeze state, nil when the deployment takes no
	// configuration.
	cfg *configurable

	// tokens verifies a holder's own bearer token, which is how the WALLET
	// identifies the person when it dials this service directly to mint a
	// capability. Nil until configure names an issuer, and a nil verifier
	// refuses every bearer rather than accepting any.
	tokens holder.Verifier

	mu    sync.Mutex
	conns map[string]*conn
}

// SetVerifier installs the holder-token verifier. Separate from New because
// the issuer arrives with the configuration, not at startup, and configure can
// replace it while requests are in flight.
func (s *Server) SetVerifier(v holder.Verifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = v
}

// verifier reads it back under the same lock. Every field configure can swap
// needs this: the read that would have bitten is a wallet call verifying
// against a verifier being replaced.
func (s *Server) verifier() holder.Verifier {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens
}

type conn struct {
	drv  mail.Driver
	used time.Time
}

func New(s store.Store, g grant.Store, requireGrant bool) *Server {
	srv := &Server{store: s, grants: g, requireGrant: requireGrant, conns: map[string]*conn{}}
	go srv.reapIdle()
	return srv
}

func (s *Server) reapIdle() {
	for range time.Tick(time.Minute) {
		s.mu.Lock()
		for sub, c := range s.conns {
			if time.Since(c.used) > idleTTL {
				_ = c.drv.Close()
				delete(s.conns, sub)
			}
		}
		s.mu.Unlock()
	}
}

// driverFor opens or reuses the mailbox for one subject.
func (s *Server) driverFor(ctx context.Context, sub string) (mail.Driver, error) {
	s.mu.Lock()
	if c, ok := s.conns[sub]; ok {
		c.used = time.Now()
		s.mu.Unlock()
		return c.drv, nil
	}
	s.mu.Unlock()

	cs := s.credStore()
	if cs == nil {
		return nil, errNotConfigured
	}
	acct, err := cs.Get(ctx, sub)
	if err != nil {
		return nil, err
	}
	var drv mail.Driver
	switch acct.Provider {
	case "imap", "":
		drv, err = imapdrv.Open(imapdrv.Config{
			Host: acct.Host, User: acct.User, Password: acct.Secret,
			OwnDomains: acct.OwnDomains,
		})
	default:
		// Graph and the Gmail API come later, in that order, because that is
		// the order of how much permission each needs from its vendor.
		return nil, fmt.Errorf("provider %q is not implemented", acct.Provider)
	}
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.conns[sub]; ok { // lost a race; keep the winner
		_ = drv.Close()
		c.used = time.Now()
		return c.drv, nil
	}
	s.conns[sub] = &conn{drv: drv, used: time.Now()}
	return drv, nil
}

// Routes returns the mux. Tool endpoints mirror the manifest exactly.
func (s *Server) Routes() *http.ServeMux {
	m := http.NewServeMux()

	m.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	m.HandleFunc("GET /readiness", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ready": true})
	})

	// The permission each tool needs. Reading and writing are different
	// sentences on the holder's approval screen, so they are different checks
	// here: a holder who approved read-only must not find the agent labelling.
	s.tool(m, "/tools/list_messages", grant.Read, s.listMessages)
	s.tool(m, "/tools/get_message", grant.Read, s.getMessage)
	s.tool(m, "/tools/get_thread", grant.Read, s.getThread)
	s.tool(m, "/tools/search", grant.Read, s.search)
	s.tool(m, "/tools/list_sent", grant.Read, s.listSent)
	s.tool(m, "/tools/account", grant.Read, s.account)
	s.tool(m, "/tools/set_labels", grant.Write, s.setLabels)
	s.tool(m, "/tools/mark_read", grant.Write, s.markRead)
	s.tool(m, "/tools/create_draft", grant.Write, s.createDraft)
	s.tool(m, "/tools/delete_draft", grant.Write, s.deleteDraft)
	s.tool(m, "/tools/changes", grant.Read, s.changes)

	s.capabilityRoutes(m)
	s.linkRoutes(m)
	s.configureRoutes(m)
	s.extensionsRoute(m)

	return m
}

// handler is one tool: it gets the acting subject and a live mailbox, and
// returns something JSON-encodable.
type handler func(ctx context.Context, sub string, drv mail.Driver, body json.RawMessage) (any, error)

func (s *Server) tool(m *http.ServeMux, path string, need grant.Permission, h handler) {
	m.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
		sub := strings.TrimSpace(r.Header.Get(SubjectHeader))
		if sub == "" {
			// Refused, not defaulted. There is no "the user" to fall back to,
			// and guessing one would be guessing whose mail to open.
			writeErr(w, http.StatusUnauthorized,
				"this call carries no acting user; the platform must assert one")
			return
		}
		if !s.configured() {
			writeErr(w, http.StatusServiceUnavailable,
				"this deployment has not been configured yet, so it has nowhere to keep a credential")
			return
		}
		if err := s.authorise(r, sub, need); err != nil {
			writeErr(w, http.StatusForbidden, err.Error())
			return
		}
		var body json.RawMessage
		if r.Body != nil {
			body, _ = readLimited(r, 1<<20)
		}
		s.mu.Lock()
		haveStore := s.store != nil
		s.mu.Unlock()
		if !haveStore {
			writeErr(w, http.StatusServiceUnavailable, "this deployment has no credential store yet")
			return
		}
		drv, err := s.driverFor(r.Context(), sub)
		if err != nil {
			if errors.Is(err, store.ErrNoAccount) {
				writeErr(w, http.StatusPreconditionFailed,
					"no mailbox is linked for this user yet")
				return
			}
			writeErr(w, http.StatusBadGateway, "the mailbox is not reachable: "+err.Error())
			return
		}
		out, err := h(r.Context(), sub, drv, body)
		if err != nil {
			status := http.StatusBadGateway
			switch {
			case errors.Is(err, mail.ErrNotFound):
				status = http.StatusNotFound
			case errors.Is(err, mail.ErrUnreadable):
				status = http.StatusUnprocessableEntity
			}
			writeErr(w, status, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, out)
	})
}

// Handler builds the http.Handler for this server.
func (s *Server) Handler() http.Handler {
	return logging(s.Routes())
}

// ---------------------------------------------------------------- tools

type listReq struct {
	Folder     string `json:"folder"`
	Limit      int    `json:"limit"`
	UnreadOnly bool   `json:"unread_only"`
	SinceDays  int    `json:"since_days"`
	Cursor     string `json:"cursor"`
}

func (r listReq) options() mail.ListOptions {
	o := mail.ListOptions{
		Folder: r.Folder, Limit: r.Limit, UnreadOnly: r.UnreadOnly, Cursor: r.Cursor,
	}
	if r.SinceDays > 0 {
		o.Since = time.Now().AddDate(0, 0, -r.SinceDays)
	}
	return o
}

func (s *Server) listMessages(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req listReq
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	return drv.List(ctx, req.options())
}

type idReq struct {
	ID       string `json:"id"`
	MaxBytes int    `json:"max_bytes"`
}

func (s *Server) getMessage(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req idReq
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	if req.ID == "" {
		return nil, errors.New("id is required")
	}
	return drv.Get(ctx, req.ID, req.MaxBytes)
}

func (s *Server) getThread(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req idReq
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	if req.ID == "" {
		return nil, errors.New("id is required")
	}
	msgs, err := drv.Thread(ctx, req.ID, req.MaxBytes)
	if err != nil {
		return nil, err
	}
	return map[string]any{"messages": msgs}, nil
}

func (s *Server) search(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req struct {
		listReq
		Query string `json:"query"`
	}
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Query) == "" {
		return nil, errors.New("query is required")
	}
	return drv.Search(ctx, req.Query, req.options())
}

func (s *Server) listSent(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req struct {
		Limit     int `json:"limit"`
		SinceDays int `json:"since_days"`
	}
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	var since time.Time
	if req.SinceDays > 0 {
		since = time.Now().AddDate(0, 0, -req.SinceDays)
	}
	msgs, err := drv.Sent(ctx, req.Limit, since)
	if err != nil {
		return nil, err
	}
	return map[string]any{"messages": msgs, "count": len(msgs)}, nil
}

// labelPrefix bounds what this connector will write into someone's mailbox.
//
// The agent chooses among labels under one namespace and cannot invent a
// top-level folder, so a confused or steered run cannot reorganise a mailbox.
const labelPrefix = "Privasys/"

func (s *Server) setLabels(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req struct {
		ID     string   `json:"id"`
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	}
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	if req.ID == "" {
		return nil, errors.New("id is required")
	}
	for _, l := range append(append([]string{}, req.Add...), req.Remove...) {
		if !strings.HasPrefix(l, labelPrefix) {
			return nil, fmt.Errorf("labels must start with %q; %q does not", labelPrefix, l)
		}
	}
	if err := drv.SetLabels(ctx, req.ID, req.Add, req.Remove); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (s *Server) markRead(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req struct {
		ID   string `json:"id"`
		Read *bool  `json:"read"`
	}
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	if req.ID == "" {
		return nil, errors.New("id is required")
	}
	read := true
	if req.Read != nil {
		read = *req.Read
	}
	if err := drv.MarkRead(ctx, req.ID, read); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (s *Server) createDraft(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req struct {
		ReplyTo string   `json:"reply_to"`
		Body    string   `json:"body"`
		CC      []string `json:"cc"`
	}
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	if req.ReplyTo == "" || strings.TrimSpace(req.Body) == "" {
		return nil, errors.New("reply_to and body are both required")
	}
	d := mail.Draft{ReplyTo: req.ReplyTo, Body: req.Body}
	for _, c := range req.CC {
		d.CC = append(d.CC, mail.Address{Addr: c})
	}
	ref, err := drv.CreateDraft(ctx, d)
	if err != nil {
		return nil, err
	}
	// The id is advisory and says so. A provider may recreate a draft under a
	// new id the moment its own interface touches one, so nothing should use
	// this as a durable handle: idempotence belongs to the record of which
	// THREAD was handled, kept on the user's Drive.
	return map[string]any{
		"draft": ref,
		"note":  "the draft id is advisory; identify handled conversations by thread, not by this id",
	}, nil
}

func (s *Server) deleteDraft(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req idReq
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	if req.ID == "" {
		return nil, errors.New("id is required")
	}
	if err := drv.DeleteDraft(ctx, req.ID); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (s *Server) changes(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req struct {
		Since   string `json:"since"`
		WaitSec int    `json:"wait_seconds"`
	}
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	wait := time.Duration(req.WaitSec) * time.Second
	if wait > 60*time.Second {
		wait = 60 * time.Second // the caller long-polls; it does not camp
	}
	changes, cursor, err := drv.Changes(ctx, req.Since, wait)
	if err != nil {
		return nil, err
	}
	return map[string]any{"changes": changes, "cursor": cursor}, nil
}

func (s *Server) account(ctx context.Context, sub string, _ mail.Driver, _ json.RawMessage) (any, error) {
	cs := s.credStore()
	if cs == nil {
		return nil, errNotConfigured
	}
	a, err := cs.Get(ctx, sub)
	if err != nil {
		return nil, err
	}
	return a.Redacted(), nil
}

// ---------------------------------------------------------------- plumbing

func decode(body json.RawMessage, v any) error {
	if len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("malformed request body: %w", err)
	}
	return nil
}

func readLimited(r *http.Request, n int64) (json.RawMessage, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	var total int64
	for {
		k, err := r.Body.Read(tmp)
		if k > 0 {
			total += int64(k)
			if total > n {
				return nil, errors.New("request body too large")
			}
			buf = append(buf, tmp[:k]...)
		}
		if err != nil {
			return buf, nil
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// logging records what was called for whom, and never what was in it. A
// connector's log must not become the copy of the mailbox the design says
// nobody keeps.
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sub := r.Header.Get(SubjectHeader)
		if len(sub) > 8 {
			sub = sub[:8] + "…"
		}
		next.ServeHTTP(w, r)
		log.Printf("%s %s sub=%s %s", r.Method, r.URL.Path, sub, time.Since(start).Round(time.Millisecond))
	})
}
