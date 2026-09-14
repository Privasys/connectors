// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"encoding/json"
	"errors"
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
			return errors.New("the user has not connected a mailbox yet, so there is nothing this assistant could be given access to. " +
				connectAdvice(r) + " Do not request access to their " + grant.Kind + " resource before the mailbox is connected: " +
				"the request would fail on their device. Once connect_mailbox has answered linked, request access and they approve it on their device")
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
	return !(errors.Is(err, store.ErrNoAccount) || errors.Is(err, broker.ErrNotApproved) || errors.Is(err, broker.ErrDeclined))
}

// connectAdvice tells the agent how a mailbox gets connected: in the
// conversation, through its own question tool and connect_mailbox (the
// decision of 2026-09-14: the whole chain runs in confidential computing and
// the session is the holder's own, in their Drive), or on this service's page
// for people who prefer it. A host that is not a plain DNS name is not
// repeated into the text.
func connectAdvice(r *http.Request) string {
	return "Ask them, with your question tool, for their email address and an app password " +
		"(for Gmail: Google account > Security > App passwords; never their sign-in password), then call connect_mailbox with them; " +
		"the credential is sealed in their own Drive. They can also do it themselves at " + linkPageURL(r) + "."
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
		acct, err := cs.Get(r.Context(), sub)
		if err != nil {
			// Approving access to a mailbox that was never linked would mint a
			// capability over nothing and read, on the holder's screen, as
			// though it had worked.
			writeErr(w, http.StatusPreconditionFailed,
				"this holder has not linked a mailbox yet, so there is nothing to approve")
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
