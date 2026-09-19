// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Privasys/connectors/mail/internal/grant"
	"github.com/Privasys/connectors/mail/internal/store"
)

// holderServer runs over the real memory store, so "the credential is gone"
// is observed the way the connector observes it: Get no longer finds it. The
// pooled connections are fakes that record being closed.
func holderServer(t *testing.T) (*Server, *store.Memory, *fakeDriver, *fakeDriver) {
	t.Helper()
	cs := store.NewMemory()
	_ = cs.Put(context.Background(), "user-1", store.Account{Provider: "imap", User: "u@example.com", Secret: "pw"})
	tools, feed := &fakeDriver{}, &fakeDriver{}
	s := &Server{
		store:  cs,
		grants: grant.NewMemory(),
		conns:  map[string]*conn{"user-1": {drv: tools, used: time.Now()}},
		feeds:  map[string]*conn{"user-1": {drv: feed, used: time.Now()}},
	}
	return s, cs, tools, feed
}

func credentialGone(cs store.Store, sub string) bool {
	_, err := cs.Get(context.Background(), sub)
	return errors.Is(err, store.ErrNoAccount)
}

func listCaps(t *testing.T, s *Server, sub string) (int, []capabilityView) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	r.Header.Set(RelaySubjectHeader, sub)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	var out struct {
		Capabilities []capabilityView `json:"capabilities"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out.Capabilities
}

func revokeCap(t *testing.T, s *Server, sub, id string) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodDelete, "/v1/capabilities/"+id, nil)
	r.Header.Set(RelaySubjectHeader, sub)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	return w.Code
}

func TestHolderListsCapabilitiesInTheSharedShape(t *testing.T) {
	s, _, _, _ := holderServer(t)
	id := mint(t, s, "user-1", []string{"read", "write"})

	code, caps := listCaps(t, s, "user-1")
	if code != http.StatusOK {
		t.Fatalf("list = %d, want 200", code)
	}
	if len(caps) != 1 {
		t.Fatalf("listed %d, want 1", len(caps))
	}
	got := caps[0]
	if got.CapabilityID != id {
		t.Errorf("capability_id = %q, want %q", got.CapabilityID, id)
	}
	if got.Kind != "mail.mailbox" {
		t.Errorf("kind = %q, want mail.mailbox", got.Kind)
	}
	// The mailbox, which is what the wallet showed the holder when they
	// approved it. Reading back a different label would make the row on their
	// screen unrecognisable.
	if got.ResourceLabel != "u@example.com" {
		t.Errorf("resource_label = %q, want the mailbox", got.ResourceLabel)
	}
	if len(got.Permissions) != 2 {
		t.Errorf("permissions = %v, want two", got.Permissions)
	}
}

// One holder cannot see another's, and the list is per holder rather than per
// service.
func TestCapabilityListIsPerHolder(t *testing.T) {
	s, _, _, _ := holderServer(t)
	mint(t, s, "user-1", []string{"read"})

	_, caps := listCaps(t, s, "user-2")
	if len(caps) != 0 {
		t.Fatalf("another holder saw %d capabilities", len(caps))
	}
}

// The promise the wallet makes when it says the service destroys its copy.
// Only this service can honour it, which is why revocation cannot be a flag in
// the wallet. With the credential go the mailbox connections opened with it:
// a pooled session that outlived it would keep reading until the reaper came.
func TestLastRevokeForgetsTheCredentialAndClosesTheConnections(t *testing.T) {
	s, cs, tools, feed := holderServer(t)
	id := mint(t, s, "user-1", []string{"read"})

	if code := revokeCap(t, s, "user-1", id); code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", code)
	}
	if !credentialGone(cs, "user-1") {
		t.Fatal("the last capability went and the mailbox credential outlived it")
	}
	if !tools.closed || !feed.closed {
		t.Fatalf("the mailbox connections outlived the credential (tools closed %v, feed closed %v)", tools.closed, feed.closed)
	}
	s.mu.Lock()
	_, pooled := s.conns["user-1"]
	_, pooledFeed := s.feeds["user-1"]
	s.mu.Unlock()
	if pooled || pooledFeed {
		t.Fatal("a closed connection was left in the pool")
	}
	_, caps := listCaps(t, s, "user-1")
	if len(caps) != 0 {
		t.Fatalf("still listed after revoke: %v", caps)
	}
	// And the next tool call is the refusal that sends the agent to the
	// holder's device, not a stale read.
	credentialNeededBody(t, callAs(t, s, "/tools/list_messages", "user-1", testApp, `{}`))
}

// The older revoke route keeps the same consequence.
func TestOlderRevokeRouteForgetsTheCredentialToo(t *testing.T) {
	s, cs, tools, _ := holderServer(t)
	id := mint(t, s, "user-1", []string{"read"})

	r := httptest.NewRequest(http.MethodDelete, "/v1/grants/"+id, nil)
	r.Header.Set(RelaySubjectHeader, "user-1")
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200", w.Code)
	}
	if !credentialGone(cs, "user-1") || !tools.closed {
		t.Fatal("the older revoke route left the credential or its connection behind")
	}
}

// The other half of that rule, and the one that would quietly break someone:
// the credential belongs to the holder and serves every app they approved, so
// it survives while any other capability is live. Destroying it on the first
// revoke would cut off access the holder never withdrew.
func TestRevokingOneOfTwoKeepsTheCredential(t *testing.T) {
	s, cs, tools, _ := holderServer(t)
	first := mint(t, s, "user-1", []string{"read"})
	// A DIFFERENT app: one live grant per app per holder, so re-approving the
	// same app replaces rather than accumulates.
	second, err := s.grantStore().Mint(context.Background(), "user-1", grant.Grant{
		Subject:     "app:0123456789abcdef0123456789abcdef",
		Permissions: []grant.Permission{grant.Read},
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	if code := revokeCap(t, s, "user-1", first); code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", code)
	}
	if credentialGone(cs, "user-1") {
		t.Fatal("the credential was destroyed while another capability was still live")
	}
	if tools.closed {
		t.Fatal("the other app's connection was closed under it")
	}

	if code := revokeCap(t, s, "user-1", second.ID); code != http.StatusNoContent {
		t.Fatalf("second revoke = %d, want 204", code)
	}
	if !credentialGone(cs, "user-1") {
		t.Fatal("the last capability went and the mailbox credential outlived it")
	}
}

func TestRevokingSomethingElsesCapabilityIsNotFound(t *testing.T) {
	s, cs, _, _ := holderServer(t)
	id := mint(t, s, "user-1", []string{"read"})

	if code := revokeCap(t, s, "user-2", id); code != http.StatusNotFound {
		t.Fatalf("cross-holder revoke = %d, want 404", code)
	}
	if credentialGone(cs, "user-1") {
		t.Fatal("someone else's revoke destroyed this holder's credential")
	}
	if _, caps := listCaps(t, s, "user-1"); len(caps) != 1 {
		t.Fatal("the owner lost their capability to someone else's revoke")
	}
}

func TestCapabilityRoutesNeedAnAuthenticatedHolder(t *testing.T) {
	s, _, _, _ := holderServer(t)
	for _, c := range []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/capabilities"},
		{http.MethodDelete, "/v1/capabilities/anything"},
	} {
		r := httptest.NewRequest(c.method, c.path, nil)
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", c.method, c.path, w.Code)
		}
	}
}
