// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package oauth

import (
	"net/http"
	"net/url"
	"regexp"
	"sync"

	"github.com/Privasys/connectors/sdk/web"
)

// Multi is several providers behind the two routes, for a connector that
// signs in with more than one for the same kind: a file store may be at
// Microsoft or at Google, and the wallet's button says which.
//
// Each provider is its own Flow with its own client, states and grant
// codes. What Multi adds is the dispatch: the start URL names the provider
// as a query parameter, and the callback is matched to the flow that
// issued its state, because a provider sends the browser back to the one
// registered redirect URI with nothing else to tell them apart.
type Multi struct {
	kind string

	mu    sync.Mutex
	flows map[string]*Flow
}

// A provider slug is a short lowercase word, the same on the start URL and
// in the connector's own records.
var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// NewMulti builds an empty set for one kind.
func NewMulti(kind string) *Multi {
	return &Multi{kind: kind, flows: map[string]*Flow{}}
}

// Add registers one provider under a slug and returns its flow, so the
// connector can set its client, its Identify and its HTTP client as it
// would on a Flow of its own. A slug that does not fit the pattern panics,
// because it is a constant in the connector's code and not an input.
func (m *Multi) Add(slug string, p Provider) *Flow {
	if !slugRe.MatchString(slug) {
		panic("oauth: provider slug " + slug + " must be a short lowercase word")
	}
	f := New(p, m.kind)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flows[slug] = f
	return f
}

// Flow returns the flow for a slug, or nil.
func (m *Multi) Flow(slug string) *Flow {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flows[slug]
}

// SchemaProperty is the sign-in button for one provider: the flow's own,
// with the provider named on the start URL so the start route can tell
// which flow to run.
func (m *Multi) SchemaProperty(r *http.Request, slug string) map[string]any {
	f := m.Flow(slug)
	if f == nil {
		return nil
	}
	prop := f.SchemaProperty(r)
	if x, ok := prop["x-privasys-oauth"].(map[string]string); ok {
		x["start_url"] += "&provider=" + url.QueryEscape(slug)
	}
	return prop
}

// Routes registers the start and the callback, once, for every provider.
func (m *Multi) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+StartPath, m.start)
	mux.HandleFunc("GET "+CallbackPath, m.callback)
}

// start runs the flow the start URL names.
func (m *Multi) start(w http.ResponseWriter, r *http.Request) {
	f := m.Flow(r.URL.Query().Get("provider"))
	if f == nil {
		w.Header().Set("Cache-Control", "no-store")
		web.WriteErr(w, http.StatusNotFound, "this service does not sign in with that provider")
		return
	}
	f.start(w, r)
}

// callback runs the flow that issued the state. A state no flow knows is
// answered as a single flow would: unknown or expired, start again.
func (m *Multi) callback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	m.mu.Lock()
	var owner *Flow
	for _, f := range m.flows {
		if f.owns(state) {
			owner = f
			break
		}
	}
	m.mu.Unlock()
	if owner == nil {
		w.Header().Set("Cache-Control", "no-store")
		web.WriteErr(w, http.StatusBadRequest, "this sign-in is unknown or has expired; start it again from your wallet")
		return
	}
	owner.callback(w, r)
}

// owns reports whether this flow started the sign-in a state names. Read
// under the flow's lock; the sweep is left to the callback that follows.
func (f *Flow) owns(state string) bool {
	if state == "" {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.states[state]
	return ok
}
