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
	// store holds each holder's credential in memory, and grants their
	// capabilities beside it. Both are lost together at a restart, and both
	// come back together with the wallet's next mint.
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

	// prove stands in for the mailbox when a test connects one; nil dials it.
	prove func(context.Context, mailboxDetails) error

	// tokens verifies a holder's own bearer token, which is how the WALLET
	// identifies the person when it dials this service directly to mint a
	// capability. Nil until configure names an issuer, and a nil verifier
	// refuses every bearer rather than accepting any.
	tokens holder.Verifier

	mu    sync.Mutex
	conns map[string]*conn
	// feeds holds a SECOND mailbox connection per subject, for the change
	// feed alone. `changes` parks its connection in IDLE for up to a minute,
	// and the driver serialises calls on one connection, so with a single
	// connection every other tool call of a run waited behind the feed (first
	// unattended runs, 2026-09-15: get_message took a minute each and the
	// run looked dead). The feed gets its own connection; the run's calls
	// share the other.
	feeds map[string]*conn
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
	srv := &Server{store: s, grants: g, requireGrant: requireGrant, conns: map[string]*conn{}, feeds: map[string]*conn{}}
	go srv.reapIdle()
	return srv
}

func (s *Server) reapIdle() {
	for range time.Tick(time.Minute) {
		s.mu.Lock()
		for _, pool := range []map[string]*conn{s.conns, s.feeds} {
			for sub, c := range pool {
				if time.Since(c.used) > idleTTL {
					_ = c.drv.Close()
					delete(pool, sub)
				}
			}
		}
		s.mu.Unlock()
	}
}

// dropConn closes and forgets both of a subject's mailbox connections: the
// tools' and the feed's. Called when the credential they were opened with
// is replaced or forgotten.
func (s *Server) dropConn(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pool := range []map[string]*conn{s.conns, s.feeds} {
		if c, ok := pool[sub]; ok {
			_ = c.drv.Close()
			delete(pool, sub)
		}
	}
}

// driverFor opens or reuses the mailbox for one subject: the connection the
// tools share.
func (s *Server) driverFor(ctx context.Context, sub string) (mail.Driver, error) {
	return s.driverIn(ctx, sub, s.conns)
}

// feedDriverFor opens or reuses the subject's change-feed connection, kept
// apart from the tools' one so a parked IDLE never delays a run.
func (s *Server) feedDriverFor(ctx context.Context, sub string) (mail.Driver, error) {
	return s.driverIn(ctx, sub, s.feeds)
}

func (s *Server) driverIn(ctx context.Context, sub string, pool map[string]*conn) (mail.Driver, error) {
	s.mu.Lock()
	if c, ok := pool[sub]; ok {
		c.used = time.Now()
		s.mu.Unlock()
		return c.drv, nil
	}
	s.mu.Unlock()

	acct, err := s.credStore().Get(ctx, sub)
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
	if c, ok := pool[sub]; ok { // lost a race; keep the winner
		_ = drv.Close()
		c.used = time.Now()
		return c.drv, nil
	}
	pool[sub] = &conn{drv: drv, used: time.Now()}
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

	// The root says what this is and that there is nothing to do here. There
	// used to be a page on which a holder typed their mailbox details; the
	// wallet's approval screen is now the only place a secret is typed. The
	// root still answers, and answers 200, so a probe or a person landing on
	// the host is told where things happen rather than shown a 404.
	m.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "Privasys Mail Connector",
			"note": "Reads one mailbox for one attested agent, under a capability the holder approved on their device. " +
				"There is no page to connect a mailbox on: the holder's wallet asks for the details on the approval screen, " +
				"and this service keeps them only in memory.",
		})
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
	// The shared list and revoke the wallet speaks, over the same store as this
	// service's own /v1/apps pair. See capability_holder.go.
	s.capabilityHolderRoutes(m)
	s.configureRoutes(m)
	s.extensionsRoute(m)
	s.mcpRoutes(m)

	return m
}

// handler is one tool: it gets the acting subject and a live mailbox, and
// returns something JSON-encodable.
type handler func(ctx context.Context, sub string, drv mail.Driver, body json.RawMessage) (any, error)

// mcpToolPrefix is where an agent's MCP client calls a tool. Every tool is
// registered at both paths from ONE closure, so the two cannot drift: the
// acting-user check, the configure gate and the capability check are the same
// code, not equivalent code.
const mcpToolPrefix = "/api/v1/mcp/tools/"

func (s *Server) tool(m *http.ServeMux, path string, need grant.Permission, h handler) {
	call := func(w http.ResponseWriter, r *http.Request) {
		sub := strings.TrimSpace(r.Header.Get(SubjectHeader))
		if sub == "" {
			// Refused, not defaulted. There is no "the user" to fall back to,
			// and guessing one would be guessing whose mail to open.
			writeErr(w, http.StatusUnauthorized,
				"this call carries no acting user; the platform must assert one")
			return
		}
		if !s.configured() {
			writeErr(w, http.StatusServiceUnavailable, errNotConfigured.Error())
			return
		}
		// The credential BEFORE the capability. After a restart both are
		// gone, and what the agent must do then is ask the holder's device
		// afresh (ask_again), which is a different instruction from "ask the
		// user to approve": a plain request would find the device's record
		// still saying approved and change nothing.
		if _, err := s.credStore().Get(r.Context(), sub); err != nil {
			if errors.Is(err, store.ErrNoAccount) {
				credentialNeeded(w)
				return
			}
			writeErr(w, http.StatusInternalServerError, "the mail connector could not read this holder's mailbox record: "+err.Error())
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
		drv, err := s.driverFor(r.Context(), sub)
		if err != nil {
			if errors.Is(err, store.ErrNoAccount) {
				credentialNeeded(w) // forgotten between the check above and here
				return
			}
			writeErr(w, http.StatusBadGateway, "the mailbox is not reachable: "+err.Error())
			return
		}
		out, err := h(r.Context(), sub, drv, body)
		if err != nil {
			if errors.Is(err, store.ErrNoAccount) {
				// The change feed opens its own connection inside the handler,
				// and answers the same way as every other tool.
				credentialNeeded(w)
				return
			}
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
	}

	m.HandleFunc("POST "+path, call)
	// The same closure, registered again where an agent's MCP client looks.
	// Derived from the manifest path rather than passed separately, so a tool
	// cannot end up mounted under one name and callable under another.
	m.HandleFunc("POST "+mcpToolPrefix+strings.TrimPrefix(path, "/tools/"), call)
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

func (s *Server) changes(ctx context.Context, sub string, _ mail.Driver, body json.RawMessage) (any, error) {
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
	// Not the tools' connection: this one parks in IDLE for the whole wait.
	drv, err := s.feedDriverFor(ctx, sub)
	if err != nil {
		return nil, err
	}
	changes, cursor, err := drv.Changes(ctx, req.Since, wait)
	if err != nil {
		return nil, err
	}
	return map[string]any{"changes": changes, "cursor": cursor}, nil
}

func (s *Server) account(ctx context.Context, sub string, _ mail.Driver, _ json.RawMessage) (any, error) {
	a, err := s.credStore().Get(ctx, sub)
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
