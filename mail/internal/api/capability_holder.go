// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/Privasys/connectors/mail/internal/grant"
)

// The two routes the WALLET speaks, so a holder can see and end what they
// approved from the device they approved it on.
//
// This service already had both: `GET /v1/apps` is the holder's own "apps with
// access" list and `DELETE /v1/grants/{id}` is its revoke. They are this
// service's own names, and the wallet cannot be taught one set of paths per
// resource service. These are the shared contract, over the same store, so a
// wallet that learns them once can show and end a capability at any service
// that implements them.
//
// The list doubles as the wallet's probe: a service that does not serve it is
// one the wallet must not offer a revoke button for, and a 404 here means
// "cannot be asked from the wallet" rather than "you have nothing".

// capabilityView is one capability as its holder sees it. Same shape Drive
// returns, because the wallet reads one shape.
type capabilityView struct {
	CapabilityID  string   `json:"capability_id"`
	Kind          string   `json:"kind"`
	Permissions   []string `json:"permissions"`
	ResourceLabel string   `json:"resource_label,omitempty"`
	SubjectAppID  string   `json:"subject_app_id"`
	CreatedUnix   int64    `json:"created_unix"`
	ExpiresUnix   int64    `json:"expires_unix,omitempty"`
}

func viewOf(g grant.Grant, mailbox string) capabilityView {
	perms := make([]string, 0, len(g.Permissions))
	for _, p := range g.Permissions {
		perms = append(perms, string(p))
	}
	v := capabilityView{
		CapabilityID: g.ID,
		Kind:         grant.Kind,
		Permissions:  perms,
		// The mailbox the capability is over, which is what the holder's wallet
		// showed them when they approved it.
		ResourceLabel: mailbox,
		SubjectAppID:  g.Subject,
		CreatedUnix:   g.IssuedAt.Unix(),
		ExpiresUnix:   g.ExpiresAt.Unix(),
	}
	return v
}

// capabilityHolderRoutes registers the shared contract.
func (s *Server) capabilityHolderRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
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
		// The mailbox is advisory here, for the label. A holder with no
		// connected mailbox can still have live capabilities in flight, so its
		// absence is not an error.
		mailbox := ""
		if acct, err := s.credStore().Get(r.Context(), sub); err == nil {
			mailbox = acct.User
		}
		now := time.Now()
		out := make([]capabilityView, 0, len(list))
		for _, g := range list {
			if !g.Live(now) {
				continue
			}
			out = append(out, viewOf(g, mailbox))
		}
		writeJSON(w, http.StatusOK, map[string]any{"capabilities": out})
	})

	m.HandleFunc("DELETE /v1/capabilities/{id}", func(w http.ResponseWriter, r *http.Request) {
		sub := s.holder(r)
		if sub == "" {
			writeErr(w, http.StatusUnauthorized, "this call is not authenticated as a holder")
			return
		}
		if err := s.grantStore().Revoke(r.Context(), sub, r.PathValue("id")); err != nil {
			if errors.Is(err, grant.ErrNoGrant) {
				// Not this holder's, or never existed. Deliberately the same
				// answer for both: whether an id exists is not something to
				// confirm to a caller who does not hold it.
				writeErr(w, http.StatusNotFound, "no such capability for this holder")
				return
			}
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.dropCredentialIfUnused(r, sub)
		w.WriteHeader(http.StatusNoContent)
	})
}

// dropCredentialIfUnused forgets the holder's mailbox credential, and closes
// the mailbox connections opened with it, once nothing is authorised to use
// it any more.
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
//
// The connections go with it. A pooled IMAP session is the credential in
// use, and one that outlived the credential would keep reading a mailbox the
// holder just withdrew until the idle reaper found it.
func (s *Server) dropCredentialIfUnused(r *http.Request, sub string) {
	remaining, err := s.grantStore().List(r.Context(), sub)
	if err != nil {
		log.Printf("[capabilities] holder %.8s…: cannot tell whether the mailbox credential is still in use: %v", sub, err)
		return
	}
	now := time.Now()
	for _, g := range remaining {
		if g.Live(now) {
			return
		}
	}
	if err := s.credStore().Delete(r.Context(), sub); err != nil {
		// The capability IS revoked and the app can no longer use it, so this
		// is not reported to the holder as a failure. It is logged because a
		// credential that outlives every grant over it is exactly the thing
		// this function exists to prevent.
		log.Printf("[capabilities] holder %.8s…: last capability revoked but the mailbox credential could not be dropped: %v", sub, err)
		return
	}
	s.dropConn(sub)
	log.Printf("[capabilities] holder %.8s…: last capability revoked, mailbox credential forgotten and its connections closed", sub)
}
