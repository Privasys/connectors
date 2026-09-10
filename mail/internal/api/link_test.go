// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Privasys/connectors/mail/internal/store"
)

// recordingStore lets a test see what was actually written, which is the only
// way to prove a secret went in and never came back out.
type recordingStore struct {
	mu   sync.Mutex
	subs map[string]store.Account
}

func newRecordingStore() *recordingStore {
	return &recordingStore{subs: map[string]store.Account{}}
}
func (r *recordingStore) Get(_ context.Context, sub string) (store.Account, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.subs[sub]
	if !ok {
		return store.Account{}, store.ErrNoAccount
	}
	return a, nil
}
func (r *recordingStore) Put(_ context.Context, sub string, a store.Account) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subs[sub] = a
	return nil
}
func (r *recordingStore) Delete(_ context.Context, sub string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.subs, sub)
	return nil
}
func (r *recordingStore) Close() error { return nil }

func linkServer(t *testing.T) (*Server, *recordingStore) {
	t.Helper()
	st := newRecordingStore()
	s, _ := newTestServer(t)
	s.store = st
	return s, st
}

func do(t *testing.T, s *Server, method, path, sub, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if sub != "" {
		r.Header.Set(SubjectHeader, sub)
	}
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	return w
}

// The page asks for a mail password, so its policy has to actually admit its
// own script. An earlier version said default-src 'none' with no script-src,
// which would have served a form that silently did nothing.
func TestLinkPagePolicyAdmitsItsOwnScript(t *testing.T) {
	s, _ := linkServer(t)
	w := do(t, s, http.MethodGet, "/", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-") {
		t.Fatalf("the policy does not admit the page's script: %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline'; script") || strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Errorf("scripts should be admitted by nonce, not by unsafe-inline: %q", csp)
	}
	if !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("the page calls its own API, which the policy must allow: %q", csp)
	}

	// The nonce in the header must be the one in the document, or the script
	// is blocked in exactly the way that is hard to notice.
	start := strings.Index(csp, "'nonce-") + len("'nonce-")
	nonce := csp[start : start+strings.Index(csp[start:], "'")]
	if nonce == "" || !strings.Contains(w.Body.String(), `nonce="`+nonce+`"`) {
		t.Fatalf("header nonce %q is not the one in the page", nonce)
	}
	if strings.Contains(w.Body.String(), "__NONCE__") {
		t.Error("the nonce placeholder was served literally")
	}
}

// A nonce that repeats is unsafe-inline with extra steps.
func TestNonceIsFreshPerResponse(t *testing.T) {
	s, _ := linkServer(t)
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		csp := do(t, s, http.MethodGet, "/", "", "").Header().Get("Content-Security-Policy")
		if seen[csp] {
			t.Fatal("the same nonce was served twice")
		}
		seen[csp] = true
	}
}

// The page must not reach out. Every byte it needs is in the document.
func TestLinkPageMakesNoExternalRequests(t *testing.T) {
	body := do(t, linkServerOnly(t), http.MethodGet, "/", "", "").Body.String()
	for _, bad := range []string{"http://", "https://", "//cdn", "integrity="} {
		if strings.Contains(body, bad) {
			t.Errorf("the page references something external (%q)", bad)
		}
	}
}

func linkServerOnly(t *testing.T) *Server {
	t.Helper()
	s, _ := linkServer(t)
	return s
}

func TestLinkNeedsAHolder(t *testing.T) {
	s, _ := linkServer(t)
	for _, c := range []struct{ method, body string }{
		{http.MethodGet, ""},
		{http.MethodPost, `{"user":"a@b.example","password":"x"}`},
		{http.MethodDelete, ""},
	} {
		if w := do(t, s, c.method, "/v1/link", "", c.body); w.Code != http.StatusUnauthorized {
			t.Errorf("%s /v1/link without a holder should be 401, got %d", c.method, w.Code)
		}
	}
}

func TestLinkRequiresBothFields(t *testing.T) {
	s, st := linkServer(t)
	for _, body := range []string{`{}`, `{"user":"a@b.example"}`, `{"password":"x"}`, `{"user":"  ","password":"x"}`} {
		if w := do(t, s, http.MethodPost, "/v1/link", "user-1", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s should be refused as incomplete, got %d", body, w.Code)
		}
	}
	if len(st.subs) != 0 {
		t.Error("an incomplete link was stored")
	}
}

// A credential that does not work must never be stored: the holder finds out
// now, from the provider's own error, rather than hours later from a triage
// run that quietly did nothing.
func TestLinkProvesTheCredentialBeforeStoring(t *testing.T) {
	s, st := linkServer(t)
	w := do(t, s, http.MethodPost, "/v1/link", "user-1",
		`{"host":"127.0.0.1:1","user":"a@b.example","password":"nope"}`)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502 when the mailbox refuses, got %d: %s", w.Code, w.Body)
	}
	if len(st.subs) != 0 {
		t.Fatal("an unproven credential was stored")
	}
}

// The secret goes in and never comes back out of any endpoint.
func TestStatusNeverReturnsTheSecret(t *testing.T) {
	s, st := linkServer(t)
	_ = st.Put(context.Background(), "user-1", store.Account{
		Provider: "imap", Host: "imap.example.com:993",
		User: "a@b.example", Secret: "super-secret-app-password",
	})

	w := do(t, s, http.MethodGet, "/v1/link", "user-1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "super-secret-app-password") {
		t.Fatalf("the secret was returned: %s", w.Body)
	}
	if !strings.Contains(w.Body.String(), "a@b.example") {
		t.Errorf("the holder should see which mailbox is linked: %s", w.Body)
	}

	// And the account tool, which an agent can call, must not leak it either.
	w2 := do(t, s, http.MethodPost, "/tools/account", "user-1", `{}`)
	if strings.Contains(w2.Body.String(), "super-secret-app-password") {
		t.Fatalf("the account tool returned the secret: %s", w2.Body)
	}
}

// Disconnecting must not silently discard the holder's separate decisions
// about which apps may act, or a re-link would restore access nobody
// re-approved.
func TestDisconnectLeavesApprovalsAlone(t *testing.T) {
	s, st := linkServer(t)
	_ = st.Put(context.Background(), "user-1", store.Account{Provider: "imap", User: "a@b.example"})
	mint(t, s, "user-1", []string{"read"})

	w := do(t, s, http.MethodDelete, "/v1/link", "user-1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("disconnect failed: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "unchanged") {
		t.Errorf("the response should say what it did NOT do: %s", w.Body)
	}
	list, _ := s.grants.List(context.Background(), "user-1")
	if len(list) != 1 {
		t.Errorf("disconnecting silently discarded %d approvals", 1-len(list))
	}
	if _, err := st.Get(context.Background(), "user-1"); err == nil {
		t.Error("the credential survived a disconnect")
	}
}

func TestDomainsAreNormalised(t *testing.T) {
	got := cleanDomains([]string{" @Example.COM ", "", "  ", "example.co.uk"})
	if len(got) != 2 || got[0] != "example.com" || got[1] != "example.co.uk" {
		t.Fatalf("domains not normalised: %#v", got)
	}
}
