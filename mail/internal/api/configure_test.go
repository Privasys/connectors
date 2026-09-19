// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/mail/internal/config"
	"github.com/Privasys/connectors/mail/internal/grant"
	"github.com/Privasys/connectors/mail/internal/store"
)

func configure(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/configure", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	return w
}

// Configuration is the identity provider and nothing else, and both fields
// default, so an empty configuration is a complete one. Nothing names a
// storage peer any more, and a body that tries is simply not read.
func TestConfigureNeedsNothingAndNamesNoPeer(t *testing.T) {
	s := freshServer(t)
	s.SetConfigurable(filepath.Join(t.TempDir(), "config.json"), config.Config{}, false)
	if s.configured() {
		t.Fatal("not configured until configure succeeds")
	}
	if held := callAs(t, s, "/tools/list_messages", "holder-1", testApp, `{}`); held.Code != http.StatusServiceUnavailable {
		t.Fatalf("every tool is held at 503 before configure, got %d", held.Code)
	}

	w := configure(t, s, `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("an empty configuration is complete: %d %s", w.Code, w.Body)
	}
	if !s.configured() {
		t.Fatal("configure did not arm the deployment")
	}
	out := w.Body.String()
	if !strings.Contains(out, config.DefaultIdpIssuer) || !strings.Contains(out, config.DefaultIdpAudience) {
		t.Fatalf("the defaults should be what is in force: %s", out)
	}
	for _, gone := range []string{"drive", "pinned", "storage"} {
		if strings.Contains(strings.ToLower(out), gone) {
			t.Fatalf("configure must not speak of a storage peer (%q): %s", gone, out)
		}
	}

	if w := configure(t, s, `{"idp_issuer":"http://plain.example"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an issuer over plain http roots identity in whoever answers the name: %d %s", w.Code, w.Body)
	}
}

// The same settings posted again (the runtime re-arms the gate at every
// boot) change nothing. A DIFFERENT identity root forgets every credential
// and capability in memory: they were approved by people an issuer this
// deployment no longer trusts named.
func TestReconfiguringTheIssuerForgetsEveryone(t *testing.T) {
	s := freshServer(t)
	s.SetConfigurable(filepath.Join(t.TempDir(), "config.json"), config.Config{}, false)
	if w := configure(t, s, `{}`); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	if w := mintWith(t, s, "holder-1", map[string]any{"user": "me@example.org", "password": "pw", "host": "imap.example.org"}); w.Code != http.StatusOK {
		t.Fatalf("mint: %d %s", w.Code, w.Body)
	}
	drv := &fakeDriver{}
	s.mu.Lock()
	s.conns["holder-1"] = &conn{drv: drv, used: time.Now()}
	s.mu.Unlock()

	if w := configure(t, s, `{}`); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	if _, err := s.credStore().Get(context.Background(), "holder-1"); err != nil {
		t.Fatalf("the same settings again must keep what is in memory: %v", err)
	}
	if drv.closed {
		t.Fatal("the same settings again closed the mailbox connection")
	}

	if w := configure(t, s, `{"idp_issuer":"https://other.example"}`); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	if _, err := s.credStore().Get(context.Background(), "holder-1"); err == nil {
		t.Fatal("a credential approved under the old issuer survived the new one")
	}
	if _, err := s.grantStore().Find(context.Background(), "holder-1", "app:"+testApp); err == nil {
		t.Fatal("a capability approved under the old issuer survived the new one")
	}
	if !drv.closed {
		t.Fatal("a connection opened under the old issuer survived the new one")
	}
	credentialNeededBody(t, callAs(t, s, "/tools/list_messages", "holder-1", testApp, `{}`))
}

// Close is what a shutdown does, and it leaves nothing: no credential, no
// capability, no open mailbox.
func TestCloseForgetsEverything(t *testing.T) {
	drv := &fakeDriver{}
	s := &Server{
		store:  store.NewMemory(),
		grants: grant.NewMemory(),
		conns:  map[string]*conn{"holder-1": {drv: drv, used: time.Now()}},
		feeds:  map[string]*conn{},
	}
	_ = s.store.Put(context.Background(), "holder-1", store.Account{User: "me@example.org", Secret: "pw"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !drv.closed {
		t.Fatal("Close left a mailbox connection open")
	}
	if _, err := s.credStore().Get(context.Background(), "holder-1"); err == nil {
		t.Fatal("Close left a credential behind")
	}
}
