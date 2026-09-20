// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package connector

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/connectors/sdk/caller"
	"github.com/Privasys/connectors/sdk/configure"
	"github.com/Privasys/connectors/sdk/credential"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/web"
)

// Authorise checks that this app may do this to this holder's resource.
//
// Two separate questions, and conflating them is how a service ends up
// enforcing less than it displayed: is there a live capability at all, and
// does it carry the permission this call needs.
//
// It is asked only once the holder's credential is known to be in memory:
// the tool wrapper answers "no credential" first (see CredentialNeeded),
// because after a restart both the credential and the capability are gone
// and the holder's device must be asked afresh, which is a different
// instruction to the agent than "ask the user to approve".
func (s *Service[T]) Authorise(r *http.Request, sub string, need grant.Permission) error {
	if !s.o.RequireGrant {
		return nil
	}
	app := caller.App(r)
	if app == "" {
		return errors.New("this call arrives with no verified calling app; the runtime must vouch for one")
	}
	g, err := s.Grants().Find(r.Context(), sub, app)
	if err != nil {
		// Written for the agent that relays them: what is missing, what the
		// user does about it, and where. Access to a resource of this kind
		// is the user's to approve, on their device.
		switch {
		case errors.Is(err, grant.ErrExpired):
			return errors.New("the user's approval for this assistant to use their " + s.o.Resource + " has expired. " +
				"Ask them whether to renew it; if they agree, call request_access for their " + s.o.Kind + " resource again, " +
				"and they approve it on their device")
		case errors.Is(err, grant.ErrNoGrant):
			return errors.New("the user has not approved this assistant's access to their " + s.o.Resource + ". " +
				"Ask them whether they want to connect it; if they agree, call request_access for their " + s.o.Kind +
				" resource, and they approve it on their device. Never ask for a password yourself: their device asks for " +
				"the " + s.o.Resource + " details on the approval screen if it needs them")
		}
		return err
	}
	if !g.Allows(need) {
		return errors.New("the holder approved " + permsText(g.Permissions) +
			" for this app, which does not cover this")
	}
	return nil
}

// CredentialNeeded is the one refusal every tool call and the change feed
// give when the holder's credential is not in this process's memory. The
// body carries two flags beside the sentence so a harness can act on it
// without parsing prose: credential_needed says what is missing, and
// needs_holder says only the holder's device can supply it.
//
// The sentence is written for the agent that relays it. The important part
// is ask_again: the device's own record may still say this service is
// approved, and a plain request_access would then return "already approved"
// and change nothing. Only ask_again makes the device ask afresh, at which
// point it sends the details it kept, or asks the holder for them, on the
// approval screen. Never a retry loop, never a page to visit.
func (s *Service[T]) CredentialNeeded(w http.ResponseWriter) {
	web.WriteJSON(w, http.StatusForbidden, map[string]any{
		"error": "the user's " + s.o.Resource + " details are not in this service's memory: it keeps none at rest, they are on the user's device. " +
			"Ask the user, then call request_access for their " + s.o.Kind + " resource WITH ask_again true, " +
			"because their device's record may still say approved and only ask_again makes it ask afresh; " +
			"their device then sends the saved details, or asks for them, on the approval screen",
		"credential_needed": true,
		"needs_holder":      true,
	})
}

func permsText(ps []grant.Permission) string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p))
	}
	return strings.Join(out, " and ")
}

// ---------------------------------------------------------------- endpoints

// View is one capability as its holder sees it. Same shape Drive returns,
// because the wallet reads one shape.
type View struct {
	CapabilityID  string   `json:"capability_id"`
	Kind          string   `json:"kind"`
	Permissions   []string `json:"permissions"`
	ResourceLabel string   `json:"resource_label,omitempty"`
	SubjectAppID  string   `json:"subject_app_id"`
	CreatedUnix   int64    `json:"created_unix"`
	ExpiresUnix   int64    `json:"expires_unix,omitempty"`
}

func viewOf(g grant.Grant, kind, label string) View {
	perms := make([]string, 0, len(g.Permissions))
	for _, p := range g.Permissions {
		perms = append(perms, string(p))
	}
	return View{
		CapabilityID: g.ID,
		Kind:         kind,
		Permissions:  perms,
		// What the capability is over, which is what the holder's wallet
		// showed them when they approved it.
		ResourceLabel: label,
		SubjectAppID:  g.Subject,
		CreatedUnix:   g.IssuedAt.Unix(),
		ExpiresUnix:   g.ExpiresAt.Unix(),
	}
}

const notAHolder = "this call is not authenticated as a holder"

// label is what the holder connected, advisory, for the wallet's rows. A
// holder with no credential in memory can still have capabilities in flight,
// so its absence is not an error.
func (s *Service[T]) label(ctx context.Context, sub string) string {
	if s.o.Label == nil {
		return ""
	}
	cred, err := s.Credentials().Get(ctx, sub)
	if err != nil {
		return ""
	}
	return s.o.Label(cred)
}

// capabilityRoutes are the holder-facing surface: what the wallet calls to
// mint, to read what the holder must answer, and to see and end what they
// approved, from the device they approved it on.
//
// `GET /v1/capabilities` and `DELETE /v1/capabilities/{id}` are the shared
// contract every resource service implements, so a wallet that learns them
// once can show and end a capability anywhere. `GET /v1/apps` and
// `DELETE /v1/grants/{id}` are the mail connector's older names for the same
// list and revoke, kept over the same store.
func (s *Service[T]) capabilityRoutes(m *http.ServeMux) {
	// POST /v1/capabilities is the WALLET's call, made as the holder after it
	// has verified this service's attestation and the requesting app's. The
	// holder is therefore whoever authenticated, and is never read from the
	// body: that is the one thing this endpoint must not accept being told.
	m.HandleFunc("POST /v1/capabilities", s.mint)

	// What this service needs from the holder before a capability can exist:
	// read by the holder's wallet, mid-approval of another app, so the
	// credential is connected on the approval screen itself and makes one
	// attested hop, phone to this enclave. Also open to a verified peer app
	// (the runtime relaying it). Nothing here is secret: a schema, and
	// nothing to approve first, because a connector asks for no folder and
	// no other resource of its own.
	m.HandleFunc("GET /v1/capabilities/setup", func(w http.ResponseWriter, r *http.Request) {
		sub := s.Holder(r)
		if sub == "" {
			sub = strings.TrimSpace(r.URL.Query().Get("subject"))
			if sub == "" || caller.App(r) == "" {
				web.WriteErr(w, http.StatusUnauthorized, "this call is not authenticated as a holder or a verified app")
				return
			}
		}
		if kind := r.URL.Query().Get("kind"); kind != "" && kind != s.o.Kind {
			web.WriteErr(w, http.StatusNotFound, "this service issues "+s.o.Kind+", not "+kind)
			return
		}
		if !s.Configured() {
			web.WriteErr(w, http.StatusServiceUnavailable, configure.ErrNotConfigured.Error())
			return
		}
		_, err := s.Credentials().Get(r.Context(), sub)
		switch {
		case err == nil:
			web.WriteJSON(w, http.StatusOK, map[string]any{"needed": false})
			return
		case !errors.Is(err, credential.ErrNone):
			web.WriteErr(w, http.StatusServiceUnavailable, s.recordError(err))
			return
		}
		out := s.question(r.Context(), nil)
		out["needed"] = true
		out["prerequisites"] = []map[string]string{}
		web.WriteJSON(w, http.StatusOK, out)
	})

	m.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		sub := s.Holder(r)
		if sub == "" {
			web.WriteErr(w, http.StatusUnauthorized, notAHolder)
			return
		}
		list, err := s.Grants().List(r.Context(), sub)
		if err != nil {
			web.WriteErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		label := s.label(r.Context(), sub)
		now := time.Now()
		out := make([]View, 0, len(list))
		for _, g := range list {
			if !g.Live(now) {
				continue
			}
			out = append(out, viewOf(g, s.o.Kind, label))
		}
		web.WriteJSON(w, http.StatusOK, map[string]any{"capabilities": out})
	})

	// The holder's own revoke. Enforcement and revocation belong next to the
	// data, so this is the button that actually removes access rather than a
	// request to be honoured elsewhere. 410 for one this holder already
	// revoked (a wallet that retried), 404 for one that is not theirs, which
	// is deliberately the same answer as "never existed".
	m.HandleFunc("DELETE /v1/capabilities/{id}", func(w http.ResponseWriter, r *http.Request) {
		sub := s.Holder(r)
		if sub == "" {
			web.WriteErr(w, http.StatusUnauthorized, notAHolder)
			return
		}
		if err := s.Grants().Revoke(r.Context(), sub, r.PathValue("id")); err != nil {
			switch {
			case errors.Is(err, grant.ErrGone):
				web.WriteErr(w, http.StatusGone, "this capability was already revoked")
			case errors.Is(err, grant.ErrNoGrant):
				web.WriteErr(w, http.StatusNotFound, "no such capability for this holder")
			default:
				web.WriteErr(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
		s.DropCredentialIfUnused(r.Context(), sub)
		w.WriteHeader(http.StatusNoContent)
	})

	// The older list.
	m.HandleFunc("GET /v1/apps", func(w http.ResponseWriter, r *http.Request) {
		sub := s.Holder(r)
		if sub == "" {
			web.WriteErr(w, http.StatusUnauthorized, notAHolder)
			return
		}
		list, err := s.Grants().List(r.Context(), sub)
		if err != nil {
			web.WriteErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if list == nil {
			list = []grant.Grant{}
		}
		web.WriteJSON(w, http.StatusOK, map[string]any{"apps": list})
	})

	// The older spelling of the revoke. Same store, same consequence: with
	// the last capability go the credential and whatever was opened with it.
	m.HandleFunc("DELETE /v1/grants/{id}", func(w http.ResponseWriter, r *http.Request) {
		sub := s.Holder(r)
		if sub == "" {
			web.WriteErr(w, http.StatusUnauthorized, notAHolder)
			return
		}
		if err := s.Grants().Revoke(r.Context(), sub, r.PathValue("id")); err != nil {
			if errors.Is(err, grant.ErrNoGrant) || errors.Is(err, grant.ErrGone) {
				web.WriteErr(w, http.StatusNotFound, "no such capability for this holder")
				return
			}
			web.WriteErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.DropCredentialIfUnused(r.Context(), sub)
		web.WriteJSON(w, http.StatusOK, map[string]bool{"revoked": true})
	})
}

// question asks the connector what the wallet must draw. A connector without
// a Setup has nothing to ask, which is only right in a test.
func (s *Service[T]) question(ctx context.Context, answers map[string]any) map[string]any {
	if s.o.Setup == nil {
		return Elicit("Connect your "+s.o.Resource+".", map[string]any{"type": "object", "properties": map[string]any{}})
	}
	return s.o.Setup.Question(ctx, answers)
}

// mint connects the credential from the wallet's answers, if any, and mints
// the capability over it, all on the one tap.
func (s *Service[T]) mint(w http.ResponseWriter, r *http.Request) {
	sub := s.Holder(r)
	if sub == "" {
		web.WriteErr(w, http.StatusUnauthorized, notAHolder)
		return
	}
	body, err := web.ReadLimited(r, 64<<10)
	if err != nil {
		web.WriteErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var req grant.Request
	if err := json.Unmarshal(body, &req); err != nil {
		web.WriteErr(w, http.StatusBadRequest, "malformed capability request")
		return
	}
	subject, perms, err := req.Validate(time.Now(), s.o.Kind)
	if err != nil {
		web.WriteErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.Configured() {
		web.WriteErr(w, http.StatusServiceUnavailable, configure.ErrNotConfigured.Error())
		return
	}

	// The holder's answers from the wallet's approval screen: connect first,
	// on the same tap, and only then mint. A 428 or a 502 here is rendered by
	// the wallet as one more question or as the provider's refusal, fields
	// kept editable. The wallet sends the answers it kept without being asked
	// after a restart here, so this branch is also how a credential comes
	// back into memory.
	var keep map[string]any
	if len(req.Setup) > 0 && s.o.Setup != nil {
		keep, err = s.o.Setup.Connect(r.Context(), sub, req.Setup)
		if err != nil {
			var ask *ElicitError
			var typed *Error
			switch {
			case errors.As(err, &ask):
				web.WriteJSON(w, http.StatusPreconditionRequired, map[string]any{"elicit": ask.Elicit})
			case errors.As(err, &typed):
				web.WriteErr(w, typed.Status, typed.Message)
			default:
				web.WriteErr(w, http.StatusBadGateway, err.Error())
			}
			return
		}
	}

	cred, err := s.Credentials().Get(r.Context(), sub)
	if err != nil {
		// Approving access to a credential that is not in memory would mint
		// a capability over nothing and read, on the holder's screen, as
		// though it had worked. The answer is the question instead, so the
		// holder connects on this same screen.
		if errors.Is(err, credential.ErrNone) {
			web.WriteJSON(w, http.StatusPreconditionRequired, map[string]any{"elicit": s.question(r.Context(), req.Setup)})
			return
		}
		log.Printf("[capabilities] mint for holder %.8s… by %s: no usable credential: %v", sub, subject, err)
		web.WriteErr(w, http.StatusInternalServerError, s.recordError(err))
		return
	}
	g, err := s.Grants().Mint(r.Context(), sub, grant.Grant{
		Subject:     subject,
		Permissions: perms,
		ExpiresAt:   time.Unix(req.ExpiresUnix, 0),
	})
	if err != nil {
		web.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// service_result is opaque to the wallet and forwarded verbatim to the
	// app, which is how the app learns its coordinates without the wallet
	// holding them as meaningful values. Deliberately says which account was
	// approved and nothing else about it.
	//
	// keep is where this service hands the wallet something to hold for it
	// and send back with the next mint: an OAuth refresh token, which the
	// holder never typed and their device would otherwise not have. A
	// credential the holder typed is already on their device, so a connector
	// keeps nothing for those and the field is absent.
	out := map[string]any{
		"capability_id": g.ID,
		"nonce":         req.Nonce,
		"expires_unix":  g.ExpiresAt.Unix(),
		"service_result": map[string]string{
			"account": s.labelOf(cred),
			"kind":    s.o.Kind,
		},
	}
	if len(keep) > 0 {
		out["keep"] = keep
	}
	web.WriteJSON(w, http.StatusOK, out)
}

func (s *Service[T]) labelOf(cred T) string {
	if s.o.Label == nil {
		return ""
	}
	return s.o.Label(cred)
}

// DropCredentialIfUnused forgets the holder's credential, and tells the
// connector to close what it opened with it, once nothing is authorised to
// use it any more.
//
// This is the promise the wallet makes on the holder's behalf when it says the
// service destroys its copy, and it is why revocation cannot be a local flag in
// the wallet: only this service can honour it. The credential lives only in
// this process's memory, so forgetting it here is the whole of the promise.
//
// Conditioned on the LAST capability going, not on any of them. The credential
// belongs to the holder and serves every app they approved, so destroying it
// while another app still holds a live capability would break access the holder
// did not withdraw. When the last one goes there is nothing left that may use
// it, and keeping it would mean holding a credential nobody is authorised
// against.
func (s *Service[T]) DropCredentialIfUnused(ctx context.Context, sub string) {
	remaining, err := s.Grants().List(ctx, sub)
	if err != nil {
		log.Printf("[capabilities] holder %.8s…: cannot tell whether the %s credential is still in use: %v", sub, s.o.Resource, err)
		return
	}
	now := time.Now()
	for _, g := range remaining {
		if g.Live(now) {
			return
		}
	}
	if err := s.Credentials().Delete(ctx, sub); err != nil {
		// The capability IS revoked and the app can no longer use it, so this
		// is not reported to the holder as a failure. It is logged because a
		// credential that outlives every grant over it is exactly the thing
		// this function exists to prevent.
		log.Printf("[capabilities] holder %.8s…: last capability revoked but the %s credential could not be dropped: %v", sub, s.o.Resource, err)
		return
	}
	if s.o.OnForget != nil {
		s.o.OnForget(sub)
	}
	log.Printf("[capabilities] holder %.8s…: last capability revoked, %s credential forgotten and its connections closed", sub, s.o.Resource)
}
