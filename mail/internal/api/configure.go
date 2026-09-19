// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/Privasys/connectors/mail/internal/config"
	"github.com/Privasys/connectors/mail/internal/grant"
	"github.com/Privasys/connectors/mail/internal/holder"
	"github.com/Privasys/connectors/mail/internal/store"
)

// Configuring is the platform's configure-then-freeze path: the runtime holds
// every other endpoint at 503 until this succeeds, and re-arms the gate on
// each restart, so a deployment cannot serve on settings nobody supplied.
//
// It carries no secret. What it names is the identity provider whose word on
// WHICH PERSON is calling this service will take, and a holder's mailbox
// credential never travels this way.

type configurable struct {
	mu      sync.RWMutex
	path    string
	current config.Config
	set     bool
}

// SetConfigurable arms the configure endpoint.
func (s *Server) SetConfigurable(path string, initial config.Config, alreadySet bool) {
	s.cfg = &configurable{path: path, current: initial, set: alreadySet}
}

func (s *Server) configured() bool {
	if s.cfg == nil {
		return true // no configure path in use, e.g. a test server
	}
	s.cfg.mu.RLock()
	defer s.cfg.mu.RUnlock()
	return s.cfg.set
}

func (s *Server) configureRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /configure", func(w http.ResponseWriter, r *http.Request) {
		if s.cfg == nil {
			writeErr(w, http.StatusBadRequest, "this deployment takes no configuration")
			return
		}
		body, err := readLimited(r, 32<<10)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		var in config.Config
		if len(body) > 0 {
			if err := json.Unmarshal(body, &in); err != nil {
				writeErr(w, http.StatusBadRequest, "malformed configuration")
				return
			}
		}
		in = in.Normalised()
		if err := in.Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := config.Save(s.cfg.path, in); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		s.cfg.mu.Lock()
		previous, wasSet := s.cfg.current, s.cfg.set
		s.cfg.current, s.cfg.set = in, true
		s.cfg.mu.Unlock()

		s.mu.Lock()
		// The issuer that decides who a HOLDER is must be swapped in one
		// breath with the record of who approved what: a window where the new
		// issuer is stored but the old one is still verifying is a window
		// where the wrong person's approval would be honoured.
		s.tokens = holder.NewJWKS(in.IdpIssuer, in.IdpAudience)
		// A different identity root means every subject in memory was named
		// by an issuer this deployment no longer trusts. What was connected
		// and approved under it is forgotten, credentials, capabilities and
		// mailbox connections alike, at the same price as a restart: each
		// holder is asked once more on their phone. The same settings posted
		// again (the runtime re-arms the gate at every boot) change nothing.
		if wasSet && previous != in {
			s.forgetEveryoneLocked()
		}
		s.mu.Unlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"configured":   true,
			"idp_issuer":   in.IdpIssuer,
			"idp_audience": in.IdpAudience,
		})
	})

	// What this deployment trusts, for an owner checking it. No secret is
	// involved, so it needs no authentication beyond reaching the app.
	m.HandleFunc("GET /configure", func(w http.ResponseWriter, r *http.Request) {
		if s.cfg == nil {
			writeJSON(w, http.StatusOK, map[string]any{"configured": true, "note": "this deployment takes no configuration"})
			return
		}
		s.cfg.mu.RLock()
		cur, set := s.cfg.current, s.cfg.set
		s.cfg.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": set,
			// Whose approvals this deployment will honour. Worth showing: an
			// operator who cannot see the issuer cannot tell whose wallet can
			// grant access to a mailbox here.
			"idp_issuer":   cur.IdpIssuer,
			"idp_audience": cur.IdpAudience,
		})
	})
}

// forgetEveryoneLocked drops every credential, capability and mailbox
// connection this process holds. Called with s.mu held.
func (s *Server) forgetEveryoneLocked() {
	for _, pool := range []map[string]*conn{s.conns, s.feeds} {
		for sub, c := range pool {
			_ = c.drv.Close()
			delete(pool, sub)
		}
	}
	if s.store != nil {
		_ = s.store.Close()
	}
	s.store = store.NewMemory()
	s.grants = grant.NewMemory()
}

// credStore reads the current store under the lock: a reconfiguration can
// replace it while a tool call is reading it.
func (s *Server) credStore() store.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store
}

// errNotConfigured is what every holder-facing path returns before configure.
var errNotConfigured = errNoStore{}

type errNoStore struct{}

func (errNoStore) Error() string {
	return "this deployment has not been configured yet, so it does not know whose approvals to honour"
}

// grantStore reads the capability store under the lock, for the same reason
// as credStore.
func (s *Server) grantStore() grant.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grants
}

// Close forgets every credential and closes every cached mailbox connection.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgetEveryoneLocked()
	return nil
}
