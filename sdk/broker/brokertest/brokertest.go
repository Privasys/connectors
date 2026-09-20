// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package brokertest is a fake runtime capability broker for tests: the
// three loopback calls a connector makes, over httptest, with an Ed25519 key
// standing in for the manager's sealed binding key.
package brokertest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Privasys/connectors/sdk/broker"
)

// Token is the container token the fake expects.
const Token = "container-token"

// Fake is the server and what it recorded.
type Fake struct {
	Server   *httptest.Server
	Resource string
	Public   ed25519.PublicKey

	mu       sync.Mutex
	private  ed25519.PrivateKey
	approved map[string]map[string]string // subject -> service_result
	declined map[string]bool
	asks     []Asked
	signed   int
}

// Asked is one request the fake was sent.
type Asked struct {
	Subject string
	Retry   bool
}

// New starts a fake broker for one resource name.
func New(t *testing.T, resource string) *Fake {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &Fake{Resource: resource, Public: pub, private: priv,
		approved: map[string]map[string]string{}, declined: map[string]bool{}}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+Token {
			http.Error(w, "no", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/v1/resources/"+resource+"/status", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		sub := r.URL.Query().Get("subject")
		f.mu.Lock()
		defer f.mu.Unlock()
		out := map[string]any{"persistent": false, "declined": f.declined[sub]}
		if sr, ok := f.approved[sub]; ok {
			out = map[string]any{"persistent": true, "capability_id": "cap-" + sub, "kind": "storage.folder",
				"permissions": []string{"read", "write"}, "label": "Meeting transcripts", "service_result": sr}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /api/v1/resources/"+resource+"/request", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var in struct {
			Subject string `json:"subject"`
			Retry   bool   `json:"retry"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.asks = append(f.asks, Asked{Subject: in.Subject, Retry: in.Retry})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case f.approved[in.Subject] != nil:
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "already_granted", "capability_id": "cap-" + in.Subject})
		case f.declined[in.Subject] && !in.Retry:
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "declined"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending", "nonce": "nonce-" + in.Subject, "app_host": "meetings.apps.example"})
		}
	})
	mux.HandleFunc("POST /api/v1/resources/sign", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var in struct {
			PayloadB64 string `json:"payload_b64"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		payload, err := base64.StdEncoding.DecodeString(in.PayloadB64)
		if err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.signed++
		f.mu.Unlock()
		sig := ed25519.Sign(f.private, payload)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"signature_b64": base64.StdEncoding.EncodeToString(sig),
			"pubkey_b64":    base64.StdEncoding.EncodeToString(f.Public),
		})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

// Client is a broker client pointed at the fake.
func (f *Fake) Client() *broker.Client {
	return broker.NewAt(f.Server.URL, Token, f.Resource)
}

// Approve records the holder's approval with Drive's coordinates.
func (f *Fake) Approve(subject, tenantID, nodeID, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approved[subject] = map[string]string{"tenant_id": tenantID, "node_id": nodeID, "path": path}
	delete(f.declined, subject)
}

// Withdraw forgets the approval, as a holder revoking in Drive does not (the
// runtime keeps saying approved); this is the runtime's own revoke.
func (f *Fake) Withdraw(subject string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.approved, subject)
}

// Decline records a refusal.
func (f *Fake) Decline(subject string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.declined[subject] = true
	delete(f.approved, subject)
}

// Asks is every request the fake was sent.
func (f *Fake) Asks() []Asked {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Asked(nil), f.asks...)
}

// Signed is how many proofs were asked for.
func (f *Fake) Signed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.signed
}

// PublicB64 is the fake's public key as the broker reports it.
func (f *Fake) PublicB64() string { return base64.StdEncoding.EncodeToString(f.Public) }

// Verify checks an AppGrant header value against the fake's key and returns
// the envelope it carried.
func (f *Fake) Verify(authorization string) (map[string]any, bool) {
	if !strings.HasPrefix(authorization, "AppGrant ") {
		return nil, false
	}
	parts := strings.SplitN(strings.TrimPrefix(authorization, "AppGrant "), ".", 2)
	if len(parts) != 2 {
		return nil, false
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !ed25519.Verify(f.Public, body, sig) {
		return nil, false
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, false
	}
	return env, true
}
