// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package drivetest is a fake Drive for tests: the app-folder routes a
// connector uses, over an httptest TLS server, checking every request's
// AppGrant proof against the fake broker's key, and answering as Drive does,
// including the refusal of an app that asks to mark its own file searchable.
package drivetest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Privasys/connectors/sdk/broker/brokertest"
	"github.com/Privasys/connectors/sdk/drive"
)

// Node is one stored file or folder.
type Node struct {
	ID       string
	ParentID string
	Kind     string
	Name     string
	Rev      int64
	Content  []byte
	Indexed  bool
}

// Fake is the server and its tree.
type Fake struct {
	Server *httptest.Server
	Broker *brokertest.Fake
	// Tenant and Root are the coordinates Approve hands the broker.
	Tenant string
	Root   string

	mu        sync.Mutex
	nodes     map[string]*Node
	next      int
	withdrawn map[string]bool // tenant -> the grant was revoked in Drive
	proofs    int
	// IndexingAllowed lets a test pretend Drive accepted an app's mark.
	IndexingAllowed bool
}

// New starts a fake Drive over TLS with one tenant and one app folder.
func New(t *testing.T, b *brokertest.Fake) *Fake {
	t.Helper()
	f := &Fake{Broker: b, Tenant: "tenant-1", Root: "root-1", nodes: map[string]*Node{}, withdrawn: map[string]bool{}}
	f.nodes[f.Root] = &Node{ID: f.Root, Kind: "folder", Name: "Meeting transcripts"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tenants/{t}/path", f.stat)
	mux.HandleFunc("PUT /v1/tenants/{t}/path", f.write)
	mux.HandleFunc("GET /v1/tenants/{t}/files/{id}", f.read)
	mux.HandleFunc("POST /v1/tenants/{t}/folders", f.mkdir)
	mux.HandleFunc("PUT /v1/tenants/{t}/nodes/{id}/indexing", f.indexing)
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

// Client is a drive client pointed at the fake over its test certificate.
func (f *Fake) Client(t *testing.T) *drive.Client {
	t.Helper()
	c, err := drive.New(f.Host(), f.Server.Client().Transport, f.Broker.Client())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Host is the fake's host:port.
func (f *Fake) Host() string { return strings.TrimPrefix(f.Server.URL, "https://") }

// Approve records the holder's approval of this app's folder with the
// broker, at the fake's coordinates.
func (f *Fake) Approve(subject string) {
	f.Broker.Approve(subject, f.Tenant, f.Root, "AppData/Meeting transcripts")
}

// Withdraw is the holder revoking the app in Drive: the broker keeps saying
// approved, Drive answers 401.
func (f *Fake) Withdraw() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdrawn[f.Tenant] = true
}

// Files lists the files under the root, by name.
func (f *Fake) Files() map[string]*Node {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]*Node{}
	for _, n := range f.nodes {
		if n.Kind == "file" {
			cp := *n
			out[n.Name] = &cp
		}
	}
	return out
}

// Proofs is how many requests carried a valid proof.
func (f *Fake) Proofs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.proofs
}

func (f *Fake) authorise(w http.ResponseWriter, r *http.Request, scope string) bool {
	env, ok := f.Broker.Verify(r.Header.Get("Authorization"))
	if !ok {
		http.Error(w, "invalid app grant", http.StatusUnauthorized)
		return false
	}
	tenant := r.PathValue("t")
	f.mu.Lock()
	withdrawn := f.withdrawn[tenant]
	f.mu.Unlock()
	if withdrawn {
		http.Error(w, "invalid app grant: revoked", http.StatusUnauthorized)
		return false
	}
	if env["sub"] != tenant || env["node"] != f.Root || env["aud"] != "privasys-drive" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	exp, _ := env["exp"].(float64)
	if time.Now().Unix() > int64(exp) || int64(exp)-time.Now().Unix() > 180 {
		http.Error(w, "proof life", http.StatusUnauthorized)
		return false
	}
	scopes, _ := env["scope"].([]any)
	has := false
	for _, s := range scopes {
		if s == scope {
			has = true
		}
	}
	if !has {
		http.Error(w, "scope", http.StatusForbidden)
		return false
	}
	f.mu.Lock()
	f.proofs++
	f.mu.Unlock()
	return true
}

func (f *Fake) view(n *Node) map[string]any {
	return map[string]any{"id": n.ID, "parent_id": n.ParentID, "kind": n.Kind, "name": n.Name,
		"rev": n.Rev, "plain_size": len(n.Content)}
}

func (f *Fake) newID() string {
	f.next++
	return fmt.Sprintf("node-%d", f.next)
}

func (f *Fake) child(parent, name string) *Node {
	for _, n := range f.nodes {
		if n.ParentID == parent && n.Name == name {
			return n
		}
	}
	return nil
}

func (f *Fake) resolve(root, path string) (*Node, *Node, string) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	parent := f.nodes[root]
	for _, seg := range segs[:len(segs)-1] {
		next := f.child(parent.ID, seg)
		if next == nil || next.Kind != "folder" {
			return nil, parent, seg
		}
		parent = next
	}
	return f.child(parent.ID, segs[len(segs)-1]), parent, segs[len(segs)-1]
}

func (f *Fake) stat(w http.ResponseWriter, r *http.Request) {
	if !f.authorise(w, r, "read") {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, _, _ := f.resolve(r.URL.Query().Get("root"), r.URL.Query().Get("path"))
	if n == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, f.view(n))
}

func (f *Fake) write(w http.ResponseWriter, r *http.Request) {
	if !f.authorise(w, r, "write") {
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	root := r.URL.Query().Get("root")
	path := r.URL.Query().Get("path")
	segs := strings.Split(strings.Trim(path, "/"), "/")
	parent := f.nodes[root]
	for _, seg := range segs[:len(segs)-1] {
		next := f.child(parent.ID, seg)
		if next == nil {
			if !strings.EqualFold(r.Header.Get("X-Drive-Parents"), "create") {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			next = &Node{ID: f.newID(), ParentID: parent.ID, Kind: "folder", Name: seg}
			f.nodes[next.ID] = next
		}
		parent = next
	}
	leaf := segs[len(segs)-1]
	if n := f.child(parent.ID, leaf); n != nil {
		n.Content = body
		n.Rev++
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(n.Rev, 10)))
		writeJSON(w, http.StatusOK, map[string]any{"id": n.ID, "rev": n.Rev})
		return
	}
	n := &Node{ID: f.newID(), ParentID: parent.ID, Kind: "file", Name: leaf, Content: body, Rev: 1}
	f.nodes[n.ID] = n
	w.Header().Set("ETag", `"1"`)
	writeJSON(w, http.StatusCreated, f.view(n))
}

func (f *Fake) read(w http.ResponseWriter, r *http.Request) {
	if !f.authorise(w, r, "read") {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[r.PathValue("id")]
	if n == nil || n.Kind != "file" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(n.Rev, 10)))
	_, _ = w.Write(n.Content)
}

func (f *Fake) mkdir(w http.ResponseWriter, r *http.Request) {
	if !f.authorise(w, r, "write") {
		return
	}
	var req struct {
		ParentID string `json:"parent_id"`
		Name     string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodes[req.ParentID] == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if f.child(req.ParentID, req.Name) != nil {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}
	n := &Node{ID: f.newID(), ParentID: req.ParentID, Kind: "folder", Name: req.Name}
	f.nodes[n.ID] = n
	writeJSON(w, http.StatusCreated, f.view(n))
}

// indexing answers as Drive does for an app principal: forbidden, because
// only the holder may mark a node searchable. IndexingAllowed flips it.
func (f *Fake) indexing(w http.ResponseWriter, r *http.Request) {
	if !f.authorise(w, r, "write") {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.IndexingAllowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	n := f.nodes[r.PathValue("id")]
	if n == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	n.Indexed = req.Enabled
	writeJSON(w, http.StatusOK, map[string]any{"node_id": n.ID, "indexing": req.Enabled})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
