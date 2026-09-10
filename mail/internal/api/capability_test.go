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
)

const testApp = "590ebdc31b63401fbbb822d5f3886c5e"

func guardedServer(t *testing.T) (*Server, *fakeDriver) {
	t.Helper()
	s, drv := newTestServer(t)
	s.requireGrant = true
	return s, drv
}

// callAs makes a tool call as a user, optionally with a verified calling app.
func callAs(t *testing.T, s *Server, path, sub, app, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set(SubjectHeader, sub)
	if app != "" {
		r.Header.Set(PeerAppHeader, app)
	}
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	return w
}

func mint(t *testing.T, s *Server, sub string, perms []string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"nonce":          "n-1",
		"subject_app_id": testApp,
		"kind":           "mail.mailbox",
		"permissions":    perms,
		"expires_unix":   time.Now().Add(24 * time.Hour).Unix(),
		"request":        map[string]any{"label": "Inbox"},
	})
	r := httptest.NewRequest(http.MethodPost, "/v1/capabilities", strings.NewReader(string(body)))
	r.Header.Set(SubjectHeader, sub)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("mint failed: %d %s", w.Code, w.Body)
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	id, _ := got["capability_id"].(string)
	if id == "" {
		t.Fatalf("no capability id in %s", w.Body)
	}
	return id
}

// With enforcement on, a caller the runtime did not vouch for gets nothing,
// whatever it claims about itself.
func TestUnvouchedAppIsRefused(t *testing.T) {
	s, _ := guardedServer(t)
	w := callAs(t, s, "/tools/list_messages", "user-1", "", `{}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 with no verified app, got %d: %s", w.Code, w.Body)
	}
}

func TestVouchedAppWithoutACapabilityIsRefused(t *testing.T) {
	s, _ := guardedServer(t)
	w := callAs(t, s, "/tools/list_messages", "user-1", testApp, `{}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 with no capability, got %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "approve") {
		t.Errorf("the refusal should tell the agent what would fix it: %s", w.Body)
	}
}

// The permission split is the point of showing the holder two words rather
// than one: read-only means read-only.
func TestReadOnlyCapabilityCannotWrite(t *testing.T) {
	s, drv := guardedServer(t)
	mint(t, s, "user-1", []string{"read"})

	if w := callAs(t, s, "/tools/list_messages", "user-1", testApp, `{}`); w.Code != http.StatusOK {
		t.Fatalf("read should be allowed: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/tools/set_labels", "/tools/mark_read", "/tools/create_draft"} {
		w := callAs(t, s, path, "user-1", testApp, `{"id":"m1","add":["Privasys/x"],"reply_to":"m1","body":"hi"}`)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s should be refused under a read-only capability, got %d: %s", path, w.Code, w.Body)
		}
	}
	if len(drv.labelsAdded) != 0 || drv.drafted.Body != "" {
		t.Error("a write reached the driver under a read-only capability")
	}
}

func TestWriteCapabilityAllowsBoth(t *testing.T) {
	s, _ := guardedServer(t)
	mint(t, s, "user-1", []string{"read", "write"})
	for _, c := range []struct{ path, body string }{
		{"/tools/list_messages", `{}`},
		{"/tools/set_labels", `{"id":"m1","add":["Privasys/needs-reply"]}`},
		{"/tools/create_draft", `{"reply_to":"m1","body":"Yes."}`},
	} {
		if w := callAs(t, s, c.path, "user-1", testApp, c.body); w.Code != http.StatusOK {
			t.Errorf("%s should be allowed: %d %s", c.path, w.Code, w.Body)
		}
	}
}

// One holder's approval must not open another holder's mailbox, and one app's
// capability must not serve another app.
func TestCapabilityIsBoundToHolderAndApp(t *testing.T) {
	s, _ := guardedServer(t)
	mint(t, s, "user-1", []string{"read"})

	otherApp := "00000000000000000000000000000001"
	if w := callAs(t, s, "/tools/list_messages", "user-1", otherApp, `{}`); w.Code != http.StatusForbidden {
		t.Errorf("another app used the capability: %d %s", w.Code, w.Body)
	}
	// A different holder has no linked mailbox at all here, which is refused
	// before the capability question even arises.
	if w := callAs(t, s, "/tools/list_messages", "user-2", testApp, `{}`); w.Code == http.StatusOK {
		t.Errorf("another holder reached a mailbox: %s", w.Body)
	}
}

// Revoking is the holder's own button and must actually stop the access.
func TestRevokeStopsAccess(t *testing.T) {
	s, _ := guardedServer(t)
	id := mint(t, s, "user-1", []string{"read"})

	if w := callAs(t, s, "/tools/list_messages", "user-1", testApp, `{}`); w.Code != http.StatusOK {
		t.Fatalf("read should work before revoke: %d", w.Code)
	}

	r := httptest.NewRequest(http.MethodDelete, "/v1/grants/"+id, nil)
	r.Header.Set(SubjectHeader, "user-1")
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke failed: %d %s", w.Code, w.Body)
	}

	if w := callAs(t, s, "/tools/list_messages", "user-1", testApp, `{}`); w.Code != http.StatusForbidden {
		t.Fatalf("access survived revoke: %d %s", w.Code, w.Body)
	}
}

func TestAppsWithAccessListing(t *testing.T) {
	s, _ := guardedServer(t)
	mint(t, s, "user-1", []string{"read", "write"})

	r := httptest.NewRequest(http.MethodGet, "/v1/apps", nil)
	r.Header.Set(SubjectHeader, "user-1")
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("listing failed: %d %s", w.Code, w.Body)
	}
	var got struct {
		Apps []struct {
			Subject     string   `json:"subject"`
			Permissions []string `json:"permissions"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Apps) != 1 || !strings.HasSuffix(got.Apps[0].Subject, testApp) {
		t.Fatalf("unexpected listing: %s", w.Body)
	}
	if len(got.Apps[0].Permissions) != 2 {
		t.Errorf("the holder should see what they approved: %v", got.Apps[0].Permissions)
	}

	// Another holder sees nothing, and specifically an empty list rather than
	// a null, so a client can render it without a special case.
	r2 := httptest.NewRequest(http.MethodGet, "/v1/apps", nil)
	r2.Header.Set(SubjectHeader, "user-2")
	w2 := httptest.NewRecorder()
	s.Routes().ServeHTTP(w2, r2)
	if !strings.Contains(w2.Body.String(), `"apps":[]`) {
		t.Errorf("another holder saw: %s", w2.Body)
	}
}

// Approving access to a mailbox nobody linked would mint a capability over
// nothing and read on the holder's screen as though it had worked.
func TestMintRefusesWhenNoMailboxIsLinked(t *testing.T) {
	s, _ := guardedServer(t)
	body, _ := json.Marshal(map[string]any{
		"nonce": "n", "subject_app_id": testApp, "kind": "mail.mailbox",
		"permissions": []string{"read"}, "expires_unix": time.Now().Add(time.Hour).Unix(),
	})
	r := httptest.NewRequest(http.MethodPost, "/v1/capabilities", strings.NewReader(string(body)))
	r.Header.Set(SubjectHeader, "user-with-no-mailbox")
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("want 412, got %d: %s", w.Code, w.Body)
	}
}

// S4 at the HTTP boundary: the holder is whoever authenticated, and a request
// that tries to name one is refused outright.
func TestMintRefusesARequestThatNamesTheHolder(t *testing.T) {
	s, _ := guardedServer(t)
	for _, field := range []string{"user", "account", "mailbox", "tenant"} {
		body, _ := json.Marshal(map[string]any{
			"nonce": "n", "subject_app_id": testApp, "kind": "mail.mailbox",
			"permissions": []string{"read"}, "expires_unix": time.Now().Add(time.Hour).Unix(),
			"request": map[string]any{field: "victim@example.com"},
		})
		r := httptest.NewRequest(http.MethodPost, "/v1/capabilities", strings.NewReader(string(body)))
		r.Header.Set(SubjectHeader, "user-1")
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("a request naming %q should be refused, got %d: %s", field, w.Code, w.Body)
		}
	}
}

func TestCapabilityEndpointsNeedAHolder(t *testing.T) {
	s, _ := guardedServer(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/v1/capabilities"},
		{http.MethodGet, "/v1/apps"},
		{http.MethodDelete, "/v1/grants/abc"},
	} {
		r := httptest.NewRequest(c.method, c.path, strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a holder should be 401, got %d", c.method, c.path, w.Code)
		}
	}
}

// The header the runtime sets is the runtime's to choose, so both spellings
// are accepted; anything unrecognised must fail closed.
func TestPeerHeaderSpellings(t *testing.T) {
	s, _ := guardedServer(t)
	mint(t, s, "user-1", []string{"read"})

	for _, h := range []string{PeerAppHeader, PeerVerifiedHeader} {
		r := httptest.NewRequest(http.MethodPost, "/tools/list_messages", strings.NewReader(`{}`))
		r.Header.Set(SubjectHeader, "user-1")
		r.Header.Set(h, testApp)
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("%s should be accepted, got %d: %s", h, w.Code, w.Body)
		}
	}
	// "true" is a vouch with no identity in it, which is not enough to pick a
	// capability, so it must not pass.
	r := httptest.NewRequest(http.MethodPost, "/tools/list_messages", strings.NewReader(`{}`))
	r.Header.Set(SubjectHeader, "user-1")
	r.Header.Set(PeerVerifiedHeader, "true")
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("a bare 'true' vouch names no app and must be refused, got %d", w.Code)
	}
}

func TestFailsClosedByDefault(t *testing.T) {
	// A Server built without opting out of enforcement must enforce. The zero
	// value being permissive would be exactly the wrong default, so the
	// constructor takes it explicitly.
	s := New(fakeStore{}, nil, true)
	if !s.requireGrant {
		t.Fatal("New(..., true) must enforce")
	}
}
