// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Privasys/connectors/mail/internal/broker"
	"github.com/Privasys/connectors/mail/internal/grant"
	"github.com/Privasys/connectors/mail/internal/store"
)

// PeerAppHeader carries the app id the RUNTIME verified from the mutual RA-TLS
// client certificate. It is set inside the trusted boundary and stripped from
// anything arriving off it.
//
// The exact name is the runtime's to choose and must be confirmed against it
// before deployment; PeerVerifiedHeader is accepted as the older spelling.
// Getting this wrong fails CLOSED — an unrecognised header means no verified
// peer, which means no access — which is the right direction to be wrong in.
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
		// The holder withdrew this service's folder in Drive: credential and
		// approvals are unreadable, whatever the runtime still records, so
		// the honest state is "nothing connected". The runtime's own record
		// (list_access) says approved; the agent must believe THIS answer.
		if errors.Is(err, store.ErrFolderWithdrawn) {
			return errors.New("the user withdrew this service's Drive folder, where their mailbox credential and their approvals were kept, " +
				"so nothing is connected any more even if an access list still says approved. " + connectAdvice(r) +
				" connect_mailbox asks their device for the folder again first, then for the credential; after it answers linked, request access to their " +
				grant.Kind + " resource again")
		}
		// Written for the agent that relays them: what is missing, what the
		// user does about it, and where. Its access to a resource of kind
		// grant.Kind is the user's to approve, and a mailbox can only be
		// approved once it is linked, which happens on this service's own page.
		//
		// ORDER MATTERS. On 2026-09-14 the refusal below sent an agent to
		// request access before the holder had linked anything; the wallet
		// then showed "nothing to approve" (412) on the holder's phone. So a
		// holder with no mailbox is told to link it FIRST, and only a holder
		// who has one is told about approvals.
		if !s.mailboxLinked(r, sub) {
			// Since 2026-09-16 the wallet connects the mailbox on the approval
			// screen itself (plan §3.7), so requesting access IS the way in;
			// connect_mailbox stays the fallback for a wallet without it.
			return errors.New("the user has not connected a mailbox yet, so there is nothing this assistant could be given access to. " +
				connectAdvice(r))
		}
		switch {
		case errors.Is(err, grant.ErrExpired):
			return errors.New("the user's approval for this assistant to use their mailbox has expired. " +
				"Ask them whether to renew it; if they agree, request access to their " + grant.Kind + " resource again, " +
				"and they approve it on their device")
		case errors.Is(err, grant.ErrNoGrant), errors.Is(err, store.ErrNoFolder):
			return errors.New("the user has not approved this assistant's access to their mailbox. " +
				"Ask them whether they want to connect it; if they agree, request access to their " + grant.Kind +
				" resource, and they approve it on their device")
		}
		return err
	}
	if !g.Allows(need) {
		return errors.New("the holder approved " + permsText(g.Permissions) +
			" for this app, which does not cover this")
	}
	return nil
}

// mailboxLinked reports whether the holder has a credential stored. Unknown
// (no store yet, or Drive unreachable) counts as linked, so the refusal that
// follows talks about approval rather than sending someone to link again.
func (s *Server) mailboxLinked(r *http.Request, sub string) bool {
	cs := s.credStore()
	if cs == nil {
		return true
	}
	_, err := cs.Get(r.Context(), sub)
	// No credential, or no folder to hold one in yet (the holder has not
	// approved this service's Drive folder): nothing is linked either way.
	// 2026-09-14 21:24 the second reading came back as "linked" and the
	// wallet was asked again for nothing.
	return !(errors.Is(err, store.ErrNoAccount) || errors.Is(err, store.ErrFolderWithdrawn) ||
		errors.Is(err, broker.ErrNotApproved) || errors.Is(err, broker.ErrDeclined))
}

// connectAdvice tells the agent how a mailbox gets connected: in the
// conversation, through its own question tool and connect_mailbox (the
// decision of 2026-09-14: the whole chain runs in confidential computing and
// the session is the holder's own, in their Drive), or on this service's page
// for people who prefer it. A host that is not a plain DNS name is not
// repeated into the text.
func connectAdvice(r *http.Request) string {
	return "Ask the user, then request access to their " + grant.Kind + " resource: their device asks them for their address and an app password on the approval screen itself " +
		"and seals them in this service, so nothing enters this conversation and you never ask for a password yourself. " +
		"If their device answers that there is nothing to approve (an older wallet), call connect_mailbox with no arguments instead: " +
		"the service then asks them on their own screen. They can also do it themselves at " + linkPageURL(r) + "."
}

// linkAdvice is kept for callers that only need the page.
func linkAdvice(r *http.Request) string { return connectAdvice(r) }

// linkPageURL names this service's linking page for the user.
func linkPageURL(r *http.Request) string {
	host := strings.ToLower(strings.TrimSpace(r.Host))
	if host != "" && dnsName.MatchString(host) {
		return "https://" + host + "/"
	}
	return "this mail connector's own page"
}

var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

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
		cs := s.credStore()
		if cs == nil {
			writeErr(w, http.StatusServiceUnavailable, errNotConfigured.Error())
			return
		}
		// The holder's answers from the wallet's approval screen (plan
		// §3.7): connect the mailbox first, on the same tap, and only then
		// mint. A 428 or a 502 here is rendered by the wallet as one more
		// question or as the provider's refusal, fields kept editable.
		if len(req.Setup) > 0 {
			if !s.connectFromSetup(w, r, cs, sub, req.Setup) {
				return
			}
		}
		acct, err := cs.Get(r.Context(), sub)
		if err != nil {
			// Approving access to a mailbox that was never linked would mint a
			// capability over nothing and read, on the holder's screen, as
			// though it had worked. The reason is logged with the holder the
			// WALLET named, because a mailbox connected under another subject
			// (the one the harness asserts on tool calls) looks exactly like no
			// mailbox from here (2026-09-14 22:19, four refused mints).
			//
			// A wallet that renders setup (§3.7) is answered with the
			// question instead, so the holder connects on this same screen.
			if setupNeeded(err) {
				writeJSON(w, http.StatusPreconditionRequired, map[string]any{"elicit": setupElicit()})
				return
			}
			log.Printf("[capabilities] mint for holder %.8s… by %s: no usable credential: %v", sub, subject, err)
			msg := "this holder has not connected a mailbox yet, so there is nothing to approve"
			switch {
			case errors.Is(err, broker.ErrNotApproved), errors.Is(err, broker.ErrDeclined):
				msg = "this holder has not given the mail connector its Drive folder, where a connected mailbox would be kept, so there is nothing to approve"
			case errors.Is(err, store.ErrFolderWithdrawn):
				msg = "this holder withdrew the mail connector's Drive folder, so the connected mailbox is gone with it; they connect the mailbox again first"
			case !errors.Is(err, store.ErrNoAccount):
				msg = "the mail connector could not read this holder's mailbox record: " + err.Error()
			}
			writeErr(w, http.StatusPreconditionFailed, msg)
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

	// What this service needs from the holder before a capability can exist
	// (plan §3.7.1): read by the holder's wallet, mid-approval of another
	// app, so the mailbox is connected on the approval screen itself and the
	// credential makes one attested hop, phone to this enclave. Also open to
	// a verified peer app (the runtime relaying it, §3.7.2). Nothing here is
	// secret: a schema and, when this service has no folder in the holder's
	// Drive yet, the ask the wallet completes first.
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
		cs := s.credStore()
		if cs == nil {
			writeErr(w, http.StatusServiceUnavailable, errNotConfigured.Error())
			return
		}
		_, err := cs.Get(r.Context(), sub)
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, map[string]any{"needed": false})
			return
		case !setupNeeded(err):
			writeErr(w, http.StatusServiceUnavailable, "the mail connector could not read this holder's mailbox record: "+err.Error())
			return
		}
		out := setupElicit()
		out["needed"] = true
		out["prerequisites"] = s.folderPrerequisites(r.Context(), cs, sub, err)
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
