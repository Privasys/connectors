// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package api is the connector's HTTP surface: the tools an attested agent
// calls, over the shell every connector shares (the sdk's package connector).
//
// What is the mail connector's here is the tool list, the mailbox connection
// each tool runs against, and the mapping of the driver's errors to statuses.
// Who the holder is, who a call acts for, the capability check, the credential
// refusal, the wallet-facing routes, the catalogue and the configure gate are
// the sdk's, so they are the same code in every connector rather than
// equivalent code.
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
	"net/http"
	"strings"
	"sync"
	"time"

	manifest "github.com/Privasys/connectors/mail"
	"github.com/Privasys/connectors/mail/internal/imapdrv"
	"github.com/Privasys/connectors/mail/internal/mail"
	"github.com/Privasys/connectors/mail/internal/store"
	"github.com/Privasys/connectors/sdk/caller"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/feed"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
	"github.com/Privasys/connectors/sdk/provider"
	"github.com/Privasys/connectors/sdk/web"
)

// The headers are the sdk's; named here so this package reads as it did.
const (
	SubjectHeader      = caller.SubjectHeader
	PeerAppHeader      = caller.PeerAppHeader
	PeerVerifiedHeader = caller.PeerVerifiedHeader
	RelaySubjectHeader = holder.RelaySubjectHeader
)

// idleTTL is how long an unused mailbox connection is kept. IMAP connections
// are cheap but not free, and a connector serving many users should not hold
// one open per user forever.
const idleTTL = 20 * time.Minute

type Server struct {
	// svc is the shell: credentials, capabilities, the holder, the routes.
	svc *connector.Service[store.Account]

	// who says from an address alone whether the mailbox is at Google, at
	// Microsoft or somewhere we reach directly; a test replaces it with a
	// table that never touches DNS.
	who *provider.Resolver

	// open opens a mailbox; a test replaces it with a fake so nothing is
	// dialled. Both the probe at connect time and the pooled connections go
	// through it.
	open func(ctx context.Context, cfg imapdrv.Config) (mail.Driver, error)

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

type conn struct {
	drv  mail.Driver
	used time.Time
}

// New builds the connector over its stores. requireGrant is taken explicitly
// rather than defaulted, because the zero value being permissive would be
// exactly the wrong default.
func New(s store.Store, g grant.Store, requireGrant bool) *Server {
	srv := &Server{conns: map[string]*conn{}, feeds: map[string]*conn{}, who: provider.Default()}
	srv.open = func(_ context.Context, cfg imapdrv.Config) (mail.Driver, error) { return imapdrv.Open(cfg) }
	srv.svc = connector.New(connector.Options[store.Account]{
		Kind:     mail.Kind,
		Resource: "mailbox",
		Name:     "Privasys Mail Connector",
		Note: "Reads one mailbox for one attested agent, under a capability the holder approved on their device. " +
			"There is no page to connect a mailbox on: the holder's wallet asks for the address on the approval screen, " +
			"then holds the browser for a Google or Microsoft sign-in, and this service keeps the credential only in memory.",
		Credentials:  s,
		Grants:       g,
		RequireGrant: requireGrant,
		Setup:        &setup{s: srv},
		Label:        func(a store.Account) string { return a.User },
		Manifest:     manifest.Manifest(),
		// A pooled IMAP session is the credential in use, and one that
		// outlived the credential would keep reading a mailbox the holder
		// just withdrew until the idle reaper found it.
		OnForget:    srv.dropConn,
		OnForgetAll: srv.closeAll,
	})
	go srv.reapIdle()
	return srv
}

// SetVerifier installs the holder-token verifier.
func (s *Server) SetVerifier(v holder.Verifier) { s.svc.SetVerifier(v) }

// SetConfigurable arms the configure endpoint.
func (s *Server) SetConfigurable(g connector.Gate) { s.svc.SetConfig(g) }

// credStore and grantStore read the current stores through the shell.
func (s *Server) credStore() store.Store  { return s.svc.Credentials() }
func (s *Server) grantStore() grant.Store { return s.svc.Grants() }

func (s *Server) configured() bool { return s.svc.Configured() }

// authorise is the shell's two-question check, kept callable here for the
// tests that read its sentences.
func (s *Server) authorise(r *http.Request, sub string, need grant.Permission) error {
	return s.svc.Authorise(r, sub, need)
}

// Close forgets every credential and closes every cached mailbox connection.
func (s *Server) Close() error { return s.svc.Close() }

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

// closeAll drops every mailbox connection this process holds.
func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pool := range []map[string]*conn{s.conns, s.feeds} {
		for sub, c := range pool {
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
	drv, err := s.open(ctx, s.driverConfig(sub, acct))
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

// driverConfig is how a mailbox is dialled: an app password with LOGIN, or
// an access token over XOAUTH2, minted from the kept refresh token as
// needed.
func (s *Server) driverConfig(sub string, acct store.Account) imapdrv.Config {
	cfg := imapdrv.Config{Host: acct.Host, User: acct.User, OwnDomains: acct.OwnDomains}
	if acct.SignedIn() {
		cfg.Token = s.tokenSource(sub)
	} else {
		cfg.Password = acct.Secret
	}
	return cfg
}

// Routes returns the mux. Tool endpoints mirror the manifest exactly.
func (s *Server) Routes() *http.ServeMux {
	m := http.NewServeMux()
	s.svc.Mount(m)

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

	return m
}

// handler is one tool: it gets the acting subject and a live mailbox, and
// returns something JSON-encodable.
type handler func(ctx context.Context, sub string, drv mail.Driver, body json.RawMessage) (any, error)

// tool registers one tool through the shell, which does the acting-user
// check, the configure gate, the credential check and the capability check
// at both paths from one closure. What is added here is the mailbox: opened
// or reused for the subject, and the driver's own errors given their status.
func (s *Server) tool(m *http.ServeMux, path string, need grant.Permission, h handler) {
	s.svc.Tool(m, path, need, func(ctx context.Context, sub string, body json.RawMessage) (any, error) {
		drv, err := s.driverFor(ctx, sub)
		if err != nil {
			if errors.Is(err, store.ErrNoAccount) {
				return nil, err // forgotten since the shell looked; the same refusal
			}
			return nil, connector.Errorf(http.StatusBadGateway, "the mailbox is not reachable: %v", err)
		}
		out, err := h(ctx, sub, drv, body)
		if err != nil {
			switch {
			case errors.Is(err, store.ErrNoAccount):
				return nil, err
			case errors.Is(err, mail.ErrNotFound):
				return nil, connector.Errorf(http.StatusNotFound, "%v", err)
			case errors.Is(err, mail.ErrUnreadable):
				return nil, connector.Errorf(http.StatusUnprocessableEntity, "%v", err)
			}
			return nil, err
		}
		return out, nil
	})
}

// Handler builds the http.Handler for this server.
func (s *Server) Handler() http.Handler {
	return web.Logging(s.Routes())
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
	if err := web.Decode(body, &req); err != nil {
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
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	if req.ID == "" {
		return nil, errors.New("id is required")
	}
	return drv.Get(ctx, req.ID, req.MaxBytes)
}

func (s *Server) getThread(ctx context.Context, _ string, drv mail.Driver, body json.RawMessage) (any, error) {
	var req idReq
	if err := web.Decode(body, &req); err != nil {
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
	if err := web.Decode(body, &req); err != nil {
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
	if err := web.Decode(body, &req); err != nil {
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
	if err := web.Decode(body, &req); err != nil {
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
	if err := web.Decode(body, &req); err != nil {
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
	if err := web.Decode(body, &req); err != nil {
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
	if err := web.Decode(body, &req); err != nil {
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
	var req feed.Request
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	// Not the tools' connection: this one parks in IDLE for the whole wait.
	drv, err := s.feedDriverFor(ctx, sub)
	if err != nil {
		return nil, err
	}
	changes, cursor, err := drv.Changes(ctx, req.Since, req.Wait())
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
