// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/mail/internal/discover"
	"github.com/Privasys/connectors/mail/internal/grant"
	"github.com/Privasys/connectors/mail/internal/store"
)

// A test must never reach the network to find a server.
func offlineDiscovery(t *testing.T) {
	t.Helper()
	prev := discover.Default
	discover.Default = &discover.Resolver{}
	t.Cleanup(func() { discover.Default = prev })
}

func mintWith(t *testing.T, s *Server, sub string, setup map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	req := map[string]any{
		"nonce":          "n-1",
		"subject_app_id": testApp,
		"kind":           "mail.mailbox",
		"permissions":    []string{"read"},
		"expires_unix":   time.Now().Add(24 * time.Hour).Unix(),
		"request":        map[string]any{"label": "Inbox"},
	}
	if setup != nil {
		req["setup"] = setup
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/v1/capabilities", strings.NewReader(string(body)))
	r.Header.Set(RelaySubjectHeader, sub)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	return w
}

// The wallet reads what this service needs before it draws the approval:
// nothing for a connected holder, the address and password (secret marked)
// for one who is not, and never anything for an unauthenticated caller.
func TestSetupSaysWhatTheHolderMustAnswer(t *testing.T) {
	s := New(fakeStore{subs: map[string]store.Account{"linked": {Provider: "imap", User: "u@example.com"}}}, grant.NewMemory(), true)
	get := func(sub string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/v1/capabilities/setup?kind=mail.mailbox", nil)
		if sub != "" {
			r.Header.Set(RelaySubjectHeader, sub)
		}
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		return w
	}
	if w := get(""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d %s", w.Code, w.Body)
	}
	w := get("linked")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"needed":false`) {
		t.Fatalf("a connected holder needs nothing: %d %s", w.Code, w.Body)
	}
	w = get("new")
	out := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(out, `"needed":true`) || !strings.Contains(out, `"secrets":["password"]`) ||
		!strings.Contains(out, `"Email address"`) || !strings.Contains(out, `"prerequisites":[]`) {
		t.Fatalf("an unconnected holder is asked for the address and the password: %d %s", w.Code, out)
	}
	if strings.Contains(out, `"host"`) {
		t.Fatalf("the server is found from the address, not asked for up front: %s", out)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/capabilities/setup?kind=storage.folder", nil)
	r.Header.Set(RelaySubjectHeader, "new")
	w = httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("another kind is not this service's: %d", w.Code)
	}
}

// A mint that carries the holder's answers connects the mailbox first: the
// provider's refusal comes back as a 502 the wallet shows beside the fields,
// a server nobody can find as a 428 with one more question, and a mint with
// no answers from a holder with no mailbox as the first question.
func TestMintWithSetupConnectsFirst(t *testing.T) {
	offlineDiscovery(t)
	st := newRecordingStore()
	s := New(st, grant.NewMemory(), true)

	w := mintWith(t, s, "holder-1", nil)
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), `"App password"`) {
		t.Fatalf("no mailbox and no answers: want the question, got %d %s", w.Code, w.Body)
	}

	w = mintWith(t, s, "holder-1", map[string]any{"user": "me@example.org", "password": "pw", "host": "127.0.0.1:1"})
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "refused these details") {
		t.Fatalf("an unreachable named server is the provider's refusal: %d %s", w.Code, w.Body)
	}
	if len(st.subs) != 0 {
		t.Fatal("an unproven credential was stored")
	}

	w = mintWith(t, s, "holder-1", map[string]any{"user": "me@nowhere.invalid", "password": "pw"})
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), `"IMAP server"`) || !strings.Contains(w.Body.String(), "imap.nowhere.invalid:993") {
		t.Fatalf("a server nobody can find is one more question, naming what was tried: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "pw") {
		t.Fatal("the password was echoed")
	}
}
