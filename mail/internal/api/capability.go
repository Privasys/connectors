// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/connectors/mail/internal/grant"
	"github.com/Privasys/connectors/mail/internal/store"
)

// PeerAppHeader carries the app id the RUNTIME verified from the mutual RA-TLS
// client certificate. It is set inside the trusted boundary and stripped from
// anything arriving off it.
//
// The exact name is the runtime's to choose and must be confirmed against it
// before deployment; PeerVerifiedHeader is accepted as the older spelling.
// Getting this wrong fails CLOSED: an unrecognised header means no verified
// peer, which means no access, which is the right direction to be wrong in.
const (
	PeerAppHeader      = "X-Privasys-Peer-App-Id"
	PeerVerifiedHeader = "X-Privasys-Peer-Verified"
)

// peerApp returns the calling app's canonical subject, or "" if the runtime
// did not vouch for one.
func peerApp(r *http.Request) string {
	for _, h := range []string{PeerAppHeader, PeerVerifiedHeader} {
		v := strings.TrimSpace(r.Header.Get(h))
		if v == "" || strings.EqualFold(v, "true") {
			continue
		}
		if s, err := grant.NormaliseSubject(v); err == nil {
			return s
		}
	}
	return ""
}

// authorise checks that this app may do this to this holder's mailbox.
//
// Two separate questions, and conflating them is how a service ends up
// enforcing less than it displayed: is there a live capability at all, and
// does it carry the permission this call needs.
//
// It is asked only once the holder's credential is known to be in memory:
// the tool wrapper answers "no credential" first (see credentialNeeded),
// because after a restart both the credential and the capability are gone
// and the holder's device must be asked afresh, which is a different
// instruction to the agent than "ask the user to approve".
func (s *Server) authorise(r *http.Request, sub string, need grant.Permission) error {
	if !s.requireGrant {
		return nil
	}
	app := peerApp(r)
	if app == "" {
		return errors.New("this call arrives with no verified calling app; the runtime must vouch for one")
	}
	g, err := s.grantStore().Find(r.Context(), sub, app)
	if err != nil {
		// Written for the agent that relays them: what is missing, what the
		// user does about it, and where. Access to a resource of kind
		// grant.Kind is the user's to approve, on their device.
		switch {
		case errors.Is(err, grant.ErrExpired):
			return errors.New("the user's approval for this assistant to use their mailbox has expired. " +
				"Ask them whether to renew it; if they agree, call request_access for their " + grant.Kind + " resource again, " +
				"and they approve it on their device")
		case errors.Is(err, grant.ErrNoGrant):
			return errors.New("the user has not approved this assistant's access to their mailbox. " +
				"Ask them whether they want to connect it; if they agree, call request_access for their " + grant.Kind +
				" resource, and they approve it on their device. Never ask for a password yourself: their device asks for " +
				"the mailbox details on the approval screen if it needs them")
		}
		return err
	}
	if !g.Allows(need) {
		return errors.New("the holder approved " + permsText(g.Permissions) +
			" for this app, which does not cover this")
	}
	return nil
}

// credentialNeeded is the one refusal every tool call and the change feed
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
func credentialNeeded(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error": "the user's mailbox details are not in this service's memory: it keeps none at rest, they are on the user's device. " +
			"Ask the user, then call request_access for their " + grant.Kind + " resource WITH ask_again true, " +
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

// capabilityRoutes are the holder-facing surface: what the wallet calls to
// mint, and what a person calls to see and revoke what they approved.
func (s *Server) capabilityRoutes(m *http.ServeMux) {
	// POST /v1/capabilities is the WALLET's call, made as the holder after it
	// has verified this service's attestation and the requesting app's. The
	// holder is therefore whoever authenticated, and is never read from the
	// body: that is the one thing this endpoint must not accept being told.
	m.HandleFunc("POST /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		sub := s.holder(r)
		if sub == "" {
			writeErr(w, http.StatusUnauthorized, "this call is not authenticated as a holder")
			return
		}
		body, err := readLimited(r, 64<<10)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		var req grant.Request
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed capability request")
			return
		}
		subject, perms, err := req.Validate(time.Now())
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if !s.configured() {
			writeErr(w, http.StatusServiceUnavailable, errNotConfigured.Error())
			return
		}
		cs := s.credStore()
		// The holder's answers from the wallet's approval screen: connect the
		// mailbox first, on the same tap, and only then mint. A 428 or a 502
		// here is rendered by the wallet as one more question or as the
		// provider's refusal, fields kept editable. The wallet sends the
		// answers it kept without being asked after a restart here, so this
		// branch is also how a credential comes back into memory.
		if len(req.Setup) > 0 {
			if !s.connectFromSetup(w, r, cs, sub, req.Setup) {
				return
			}
		}
		acct, err := cs.Get(r.Context(), sub)
		if err != nil {
			// Approving access to a mailbox that is not in memory would mint
			// a capability over nothing and read, on the holder's screen, as
			// though it had worked. The answer is the question instead, so
			// the holder connects on this same screen.
			if errors.Is(err, store.ErrNoAccount) {
				writeJSON(w, http.StatusPreconditionRequired, map[string]any{"elicit": setupElicit()})
				return
			}
			log.Printf("[capabilities] mint for holder %.8s… by %s: no usable credential: %v", sub, subject, err)
			writeErr(w, http.StatusInternalServerError, "the mail connector could not read this holder's mailbox record: "+err.Error())
			return
		}
		g, err := s.grantStore().Mint(r.Context(), sub, grant.Grant{
			Subject:     subject,
			Permissions: perms,
			ExpiresAt:   time.Unix(req.ExpiresUnix, 0),
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// service_result is opaque to the wallet and forwarded verbatim to the
		// app, which is how the app learns its coordinates without the wallet
		// holding them as meaningful values. Deliberately says which mailbox
		// was approved and nothing else about it.
		//
		// There is no "keep" field. It is where this service would hand the
		// wallet something to hold for it and send back with the next mint,
		// because nothing is kept here: an OAuth refresh token for a Graph or
		// Gmail mailbox would go there. An IMAP credential is what the holder
		// typed, which their device already keeps.
		writeJSON(w, http.StatusOK, map[string]any{
			"capability_id": g.ID,
			"nonce":         req.Nonce,
			"expires_unix":  g.ExpiresAt.Unix(),
			"service_result": map[string]string{
				"account": acct.User,
				"kind":    grant.Kind,
			},
		})
	})

	// What this service needs from the holder before a capability can exist:
	// read by the holder's wallet, mid-approval of another app, so the
	// mailbox is connected on the approval screen itself and the credential
	// makes one attested hop, phone to this enclave. Also open to a verified
	// peer app (the runtime relaying it). Nothing here is secret: a schema,
	// and nothing to approve first, because this service asks for no folder
	// and no other resource of its own.
	m.HandleFunc("GET /v1/capabilities/setup", func(w http.ResponseWriter, r *http.Request) {
		sub := s.holder(r)
		if sub == "" {
			sub = strings.TrimSpace(r.URL.Query().Get("subject"))
			if sub == "" || peerApp(r) == "" {
				writeErr(w, http.StatusUnauthorized, "this call is not authenticated as a holder or a verified app")
				return
			}
		}
		if kind := r.URL.Query().Get("kind"); kind != "" && kind != grant.Kind {
			writeErr(w, http.StatusNotFound, "this service issues "+grant.Kind+", not "+kind)
			return
		}
		if !s.configured() {
			writeErr(w, http.StatusServiceUnavailable, errNotConfigured.Error())
			return
		}
		_, err := s.credStore().Get(r.Context(), sub)
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, map[string]any{"needed": false})
			return
		case !errors.Is(err, store.ErrNoAccount):
			writeErr(w, http.StatusServiceUnavailable, "the mail connector could not read this holder's mailbox record: "+err.Error())
			return
		}
		out := setupElicit()
		out["needed"] = true
		out["prerequisites"] = []map[string]string{}
		writeJSON(w, http.StatusOK, out)
	})

	// The holder's own "apps with access" list, and their revoke. Enforcement
	// and revocation belong next to the data, so this is the button that
	// actually removes access rather than a request to be honoured elsewhere.
	m.HandleFunc("GET /v1/apps", func(w http.ResponseWriter, r *http.Request) {
		sub := s.holder(r)
		if sub == "" {
			writeErr(w, http.StatusUnauthorized, "this call is not authenticated as a holder")
			return
		}
		list, err := s.grantStore().List(r.Context(), sub)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if list == nil {
			list = []grant.Grant{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"apps": list})
	})

	// The older spelling of the revoke. Same store, same consequence: with the
	// last capability go the credential and the mailbox connections.
	m.HandleFunc("DELETE /v1/grants/{id}", func(w http.ResponseWriter, r *http.Request) {
		sub := s.holder(r)
		if sub == "" {
			writeErr(w, http.StatusUnauthorized, "this call is not authenticated as a holder")
			return
		}
		if err := s.grantStore().Revoke(r.Context(), sub, r.PathValue("id")); err != nil {
			if errors.Is(err, grant.ErrNoGrant) {
				writeErr(w, http.StatusNotFound, "no such capability for this holder")
				return
			}
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.dropCredentialIfUnused(r, sub)
		writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
	})
}

// RelaySubjectHeader is the identity the RUNTIME asserts for a person behind
// the sealed transport. The session-relay middleware strips any inbound value
// on every path before dispatching, so a caller cannot supply it; that
// stripping is the whole reason this header can be trusted and the reason it
// is not the same header an app uses to name the user it acts for.
const RelaySubjectHeader = "X-Privasys-Sub"

// holder is the authenticated PERSON, established two ways and no others: the
// relay-asserted subject, or a bearer token from the platform's identity
// provider that this service verifies itself.
//
// It deliberately does NOT read X-Privasys-On-Behalf-Of, and an earlier
// version of this file did, which was a privilege escalation rather than an
// untidiness. That header is written by the calling app. Trusting it here
// would have let the very app that wants access to a mailbox mint itself the
// capability granting it, for any user it cared to name, without a wallet
// screen ever being drawn. The app names the user it ACTS FOR; only the
// platform, or the person's own token, names the user who DECIDES.
//
// Failing closed matters more here than a helpful error, so an unverifiable
// token is the same answer as no token: this call is not a holder.
func (s *Server) holder(r *http.Request) string {
	if sub := strings.TrimSpace(r.Header.Get(RelaySubjectHeader)); sub != "" {
		return sub
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	v := s.verifier()
	if !strings.HasPrefix(auth, "Bearer ") || v == nil {
		return ""
	}
	id, err := v.Verify(r.Context(), strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")))
	if err != nil || id == nil {
		return ""
	}
	return id.Sub
}
