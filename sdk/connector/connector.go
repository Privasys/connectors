// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package connector is the shell every connector shares: the part a
// third-party connector gets dangerously wrong, so it is deliberately here to
// be copied verbatim rather than reimplemented.
//
// A connector is a driver, a schema, a probe and a tool list. Everything else
// is this package and the ones beside it: who the holder is (package holder),
// who a call acts for and which app makes it (package caller), the capability
// a holder minted (package grant), the credential that lives only in memory
// (package credential), the wallet-facing routes that connect and mint on one
// tap, the refusals an agent can act on, the catalogue (package mcp) and the
// configure-then-freeze gate (package configure).
//
// Two rules shape everything here.
//
// The acting user is asserted by the platform, never by the caller. It
// arrives as X-Privasys-On-Behalf-Of on a leg the runtime has already
// authenticated. An app that could name its own subject could read anyone's
// data, so a request without one is refused rather than defaulted.
//
// The holder is a different person from the acting user, established with
// different evidence: the relay's own header or a token the connector
// verifies, never anything the calling app writes. If the same header were
// good enough for both, the app that wants access could grant itself access
// and no wallet screen would ever be drawn.
package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/Privasys/connectors/sdk/caller"
	"github.com/Privasys/connectors/sdk/configure"
	"github.com/Privasys/connectors/sdk/credential"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
	"github.com/Privasys/connectors/sdk/mcp"
	"github.com/Privasys/connectors/sdk/web"
)

// Error is an HTTP status with a sentence for the caller. A tool handler or a
// Setup returns one when the status matters; any other error is a 502, the
// provider's fault until proven otherwise.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// Errorf builds an Error.
func Errorf(status int, format string, args ...any) *Error {
	return &Error{Status: status, Message: fmt.Sprintf(format, args...)}
}

// ElicitError is a Setup asking the holder one more question: the mint
// answers 428 with the elicitation, the wallet draws it on the approval
// screen and mints again with all the answers.
type ElicitError struct {
	Elicit map[string]any
}

func (e *ElicitError) Error() string { return "the holder must answer one more question" }

// Elicit builds an elicitation in the shape the wallet draws: a sentence, a
// JSON schema for the answers, and which of them are secrets (masked as they
// are typed, sent once, never echoed).
func Elicit(message string, schema map[string]any, secrets ...string) map[string]any {
	out := map[string]any{
		"message":         message,
		"requestedSchema": schema,
	}
	if len(secrets) > 0 {
		out["secrets"] = secrets
	}
	return out
}

// Setup is the connector's side of connecting a credential on the wallet's
// approval screen: what its question is, and how it proves and keeps the
// answers. The three things a connector plugs in are this, the label of what
// was connected, and what to drop when the credential goes (Options).
type Setup interface {
	// Question is what the wallet draws before it can mint, given the
	// answers it has accumulated so far (nil at the first step). A connector
	// with two steps decides the second from the first.
	Question(ctx context.Context, answers map[string]any) map[string]any

	// Connect proves the answers against the provider, keeps the credential
	// in memory for sub, and returns what the wallet should keep for this
	// service and send back with the next mint (nil when there is nothing:
	// the holder's own answers are already on their device). An
	// *ElicitError asks one more question; an *Error carries its status (a
	// 502 for a provider that refused the details); anything else is a 502.
	Connect(ctx context.Context, sub string, answers map[string]any) (keep map[string]any, err error)
}

// Gate is what the shell needs from the configure-then-freeze state. Leave
// Options.Config nil for a deployment that takes no configuration; never a
// typed nil pointer.
type Gate interface {
	Configured() bool
	Digest() ([]byte, bool)
	Routes(m *http.ServeMux, apply func(issuer, audience string, identityChanged bool))
}

// Options describe one connector to the shell.
type Options[T any] struct {
	// Kind is the one capability kind this connector issues, "mail.mailbox".
	Kind string
	// Resource is the noun in sentences to the agent and the holder:
	// "mailbox", "calendar".
	Resource string
	// Name and Note are what GET / says: what this service is, and that
	// there is no page to connect on.
	Name string
	Note string

	// Credentials holds each holder's credential in memory. Grants holds
	// their capabilities beside it. Both are lost together at a restart, and
	// both come back together with the wallet's next mint.
	Credentials credential.Store[T]
	Grants      grant.Store

	// RequireGrant is the fail-closed switch. On the platform every tool call
	// must be covered by a capability the holder approved. It can be turned
	// off only for development, deliberately and explicitly, because a
	// connector that serves without checking is the whole risk.
	RequireGrant bool

	// Setup connects a credential from the wallet's answers.
	Setup Setup
	// Label names what a holder connected, for the mint's service_result
	// and the capability list's resource_label: the address, never a secret.
	Label func(cred T) string

	// Manifest is the embedded privasys.json, parsed; nil serves no
	// catalogue, which is only right in a test.
	Manifest *mcp.Manifest
	// Config is the configure-then-freeze gate, nil when the deployment
	// takes none.
	Config Gate

	// OnForget is told when a holder's credential has been dropped, so the
	// connector closes whatever it opened with it (a pooled session is the
	// credential in use). OnForgetAll is the same for everyone at once.
	OnForget    func(sub string)
	OnForgetAll func()
}

// Service is the shell for one connector.
type Service[T any] struct {
	o Options[T]

	mu sync.Mutex
	// verifier checks a holder's own bearer token, which is how the WALLET
	// identifies the person when it dials this service directly to mint a
	// capability. Nil until something names an issuer, and a nil verifier
	// refuses every bearer rather than accepting any. Read under the lock:
	// configure can replace it while a wallet call is verifying.
	verifier holder.Verifier
}

// New builds the shell. RequireGrant is taken from the options explicitly
// rather than defaulted, because the zero value being permissive would be
// exactly the wrong default.
func New[T any](o Options[T]) *Service[T] {
	if o.Credentials == nil {
		o.Credentials = credential.NewMemory[T]()
	}
	if o.Grants == nil {
		o.Grants = grant.NewMemory()
	}
	if o.Resource == "" {
		o.Resource = "resource"
	}
	return &Service[T]{o: o}
}

// Kind is the capability kind this connector issues.
func (s *Service[T]) Kind() string { return s.o.Kind }

// RequireGrant reports whether tool calls are checked against capabilities.
func (s *Service[T]) RequireGrant() bool { return s.o.RequireGrant }

// Credentials is the store. Read through the shell so a reconfiguration and a
// tool call agree on which one is current.
func (s *Service[T]) Credentials() credential.Store[T] {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.o.Credentials
}

// Grants is the capability store.
func (s *Service[T]) Grants() grant.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.o.Grants
}

// SetVerifier installs the holder-token verifier. Separate from New because
// the issuer arrives with the configuration, not at startup, and configure
// can replace it while requests are in flight.
func (s *Service[T]) SetVerifier(v holder.Verifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifier = v
}

// Verifier reads it back under the same lock.
func (s *Service[T]) Verifier() holder.Verifier {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifier
}

// Holder is the authenticated PERSON behind a request, or "".
func (s *Service[T]) Holder(r *http.Request) string {
	return holder.Of(r, s.Verifier())
}

// Configured reports whether the deployment may serve anything but
// /configure.
func (s *Service[T]) Configured() bool {
	s.mu.Lock()
	g := s.o.Config
	s.mu.Unlock()
	if g == nil {
		return true // no configure path in use, e.g. a test server
	}
	return g.Configured()
}

// reconfigured is what the gate calls after a successful configure.
//
// The issuer that decides who a HOLDER is must be swapped in one breath with
// the record of who approved what: a window where the new issuer is stored
// but the old one is still verifying is a window where the wrong person's
// approval would be honoured. A different identity root means every subject
// in memory was named by an issuer this deployment no longer trusts, so what
// was connected and approved under it is forgotten, at the same price as a
// restart: each holder is asked once more on their phone.
func (s *Service[T]) reconfigured(issuer, audience string, identityChanged bool) {
	s.mu.Lock()
	s.verifier = holder.NewJWKS(issuer, audience)
	if identityChanged {
		s.forgetEveryoneLocked()
	}
	s.mu.Unlock()
}

// ForgetEveryone drops every credential and capability this process holds,
// and tells the connector to close what it opened with them.
func (s *Service[T]) ForgetEveryone() {
	s.mu.Lock()
	s.forgetEveryoneLocked()
	s.mu.Unlock()
}

func (s *Service[T]) forgetEveryoneLocked() {
	_ = s.o.Credentials.Close()
	_ = s.o.Grants.Close()
	if s.o.OnForgetAll != nil {
		s.o.OnForgetAll()
	}
}

// Close forgets every credential and capability. What a shutdown does, and it
// leaves nothing.
func (s *Service[T]) Close() error {
	s.ForgetEveryone()
	return nil
}

// Mount registers everything the shell serves on m: health and readiness,
// the root, the wallet-facing capability routes, configure, the attestation
// extensions and the catalogue. The connector registers its tools with Tool.
func (s *Service[T]) Mount(m *http.ServeMux) {
	m.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		web.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	m.HandleFunc("GET /readiness", func(w http.ResponseWriter, r *http.Request) {
		web.WriteJSON(w, http.StatusOK, map[string]any{"ready": true})
	})

	// The root says what this is and that there is nothing to do here. The
	// wallet's approval screen is the only place a secret is typed. The root
	// answers 200, so a probe or a person landing on the host is told where
	// things happen rather than shown a 404.
	m.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		web.WriteJSON(w, http.StatusOK, map[string]any{"service": s.o.Name, "note": s.o.Note})
	})

	s.capabilityRoutes(m)
	if s.o.Config != nil {
		s.o.Config.Routes(m, s.reconfigured)
		configure.ExtensionsRoute(m, s.o.Config)
	} else {
		configure.ExtensionsRoute(m, nil)
	}
	if s.o.Manifest != nil {
		s.o.Manifest.CatalogueRoute(m)
	}
}

// Handler is one tool: it gets the acting subject, whose credential is known
// to be in memory and whose approval covers the call, and returns something
// JSON-encodable.
type Handler func(ctx context.Context, sub string, body json.RawMessage) (any, error)

// Tool registers one tool at the connector's path and at the agent's, from
// ONE closure, so the two cannot drift: the acting-user check, the configure
// gate, the credential check and the capability check are the same code, not
// equivalent code. A second copy of those checks is a second place for them
// to be relaxed.
//
// The order is the point. The credential BEFORE the capability: after a
// restart both are gone, and what the agent must do then is ask the holder's
// device afresh (ask_again), which is a different instruction from "ask the
// user to approve", because a plain request would find the device's record
// still saying approved and change nothing.
func (s *Service[T]) Tool(m *http.ServeMux, path string, need grant.Permission, h Handler) {
	call := func(w http.ResponseWriter, r *http.Request) {
		sub := caller.ActingUser(r)
		if sub == "" {
			// Refused, not defaulted. There is no "the user" to fall back to,
			// and guessing one would be guessing whose data to open.
			web.WriteErr(w, http.StatusUnauthorized,
				"this call carries no acting user; the platform must assert one")
			return
		}
		if !s.Configured() {
			web.WriteErr(w, http.StatusServiceUnavailable, configure.ErrNotConfigured.Error())
			return
		}
		if _, err := s.Credentials().Get(r.Context(), sub); err != nil {
			if errors.Is(err, credential.ErrNone) {
				s.CredentialNeeded(w)
				return
			}
			web.WriteErr(w, http.StatusInternalServerError, s.recordError(err))
			return
		}
		if err := s.Authorise(r, sub, need); err != nil {
			web.WriteErr(w, http.StatusForbidden, err.Error())
			return
		}
		body, err := web.ReadLimited(r, 1<<20)
		if err != nil {
			web.WriteErr(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		out, err := h(r.Context(), sub, body)
		if err != nil {
			var typed *Error
			switch {
			case errors.Is(err, credential.ErrNone):
				// Forgotten between the check above and here, or by a
				// handler that opens its own connection: the same answer.
				s.CredentialNeeded(w)
			case errors.As(err, &typed):
				web.WriteErr(w, typed.Status, typed.Message)
			default:
				web.WriteErr(w, http.StatusBadGateway, err.Error())
			}
			return
		}
		web.WriteJSON(w, http.StatusOK, out)
	}
	m.HandleFunc("POST "+path, call)
	m.HandleFunc("POST "+mcp.AgentPath(path), call)
}

func (s *Service[T]) recordError(err error) string {
	return fmt.Sprintf("this service could not read this holder's %s record: %v", s.o.Resource, err)
}

// SetConfig installs the configure-then-freeze gate. Separate from New
// because the connector loads its stored settings after it has built the
// shell, and before it mounts the routes.
func (s *Service[T]) SetConfig(g Gate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.o.Config = g
}
