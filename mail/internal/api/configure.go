// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/Privasys/connectors/mail/internal/config"
	"github.com/Privasys/connectors/mail/internal/holder"
	"github.com/Privasys/connectors/mail/internal/store"
)

// Configuring is the platform's configure-then-freeze path: the runtime holds
// every other endpoint at 503 until this succeeds, and re-arms the gate on
// each restart, so a deployment cannot serve on settings nobody supplied.
//
// It carries no secret. Everything here names a PEER, and a holder's mailbox
// credential never travels this way.

// StoreBuilder turns a configuration into a credential store. Injected so this
// package does not need to know how a store is built, and so a test can build
// one without a runtime.
type StoreBuilder func(config.Config) (store.Store, error)

type configurable struct {
	mu      sync.RWMutex
	path    string
	build   StoreBuilder
	current config.Config
	set     bool
}

// SetConfigurable arms the configure endpoint.
func (s *Server) SetConfigurable(path string, build StoreBuilder, initial config.Config, alreadySet bool) {
	s.cfg = &configurable{path: path, build: build, current: initial, set: alreadySet}
}

func (s *Server) configured() bool {
	if s.cfg == nil {
		return true // no configure path in use, e.g. the development store
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
		if err := json.Unmarshal(body, &in); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed configuration")
			return
		}
		in = in.Normalised()
		if err := in.Validate(); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}

		// Build BEFORE saving. A configuration that cannot produce a working
		// store should be refused while the operator is still watching, not
		// persisted so that every later boot fails on it.
		st, err := s.cfg.build(in)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "these settings do not work: "+err.Error())
			return
		}
		if err := config.Save(s.cfg.path, in); err != nil {
			_ = st.Close()
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		s.mu.Lock()
		old := s.store
		s.store = st
		// The issuer that decides who a HOLDER is arrives with the same
		// configuration as the peer that stores their credential, and must be
		// swapped in the same breath: a window where the new issuer is stored
		// but the old one is still verifying is a window where the wrong
		// person's approval would be honoured.
		s.tokens = holder.NewJWKS(in.IdpIssuer, in.IdpAudience)
		// Cached mailbox connections belong to the previous store's
		// credentials, so they must not survive a reconfiguration.
		for sub, c := range s.conns {
			_ = c.drv.Close()
			delete(s.conns, sub)
		}
		s.mu.Unlock()
		if old != nil {
			_ = old.Close()
		}

		s.cfg.mu.Lock()
		s.cfg.current, s.cfg.set = in, true
		s.cfg.mu.Unlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"configured": true,
			"drive_host": in.DriveHost,
			"pinned_app": in.DriveAppID,
			"pinned_build": func() string {
				if in.DriveDigest == "" {
					return "(any build of that app)"
				}
				return in.DriveDigest
			}(),
		})
	})

	// What this deployment is pointed at, for an owner checking it. No secret
	// is involved, so it needs no authentication beyond reaching the app.
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
			"drive_host": cur.DriveHost,
			"pinned_app": cur.DriveAppID,
			// Whose approvals this deployment will honour. Worth showing: an
			// operator who cannot see the issuer cannot tell whose wallet can
			// grant access to a mailbox here.
			"idp_issuer":   cur.IdpIssuer,
			"idp_audience": cur.IdpAudience,
		})
	})
}

// credStore reads the current store under the lock.
//
// It became necessary the moment configure could swap one in: every direct
// read of the field was a race with a reconfiguration, and the one that would
// have bitten is a tool call reading a store that was being closed.
func (s *Server) credStore() store.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store
}

// errNotConfigured is what every holder-facing path returns before configure.
var errNotConfigured = errNoStore{}

type errNoStore struct{}

func (errNoStore) Error() string {
	return "this deployment has not been configured yet, so it has nowhere to keep a credential"
}

// SetStore installs the credential store after construction, for the
// configure path where it does not exist yet at startup.
func (s *Server) SetStore(st store.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = st
}

// Close releases the store and every cached mailbox connection.
func (s *Server) Close() error {
	s.mu.Lock()
	st := s.store
	for sub, c := range s.conns {
		_ = c.drv.Close()
		delete(s.conns, sub)
	}
	s.store = nil
	s.mu.Unlock()
	if st != nil {
		return st.Close()
	}
	return nil
}
