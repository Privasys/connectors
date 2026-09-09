// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/mail/internal/mail"
	"github.com/Privasys/connectors/mail/internal/store"
)

// fakeStore has one linked account, for one subject.
type fakeStore struct{ subs map[string]store.Account }

func (f fakeStore) Get(_ context.Context, sub string) (store.Account, error) {
	a, ok := f.subs[sub]
	if !ok {
		return store.Account{}, store.ErrNoAccount
	}
	return a, nil
}
func (f fakeStore) Put(context.Context, string, store.Account) error { return nil }
func (f fakeStore) Delete(context.Context, string) error             { return nil }
func (f fakeStore) Close() error                                     { return nil }

// fakeDriver records what it was asked to do.
type fakeDriver struct {
	labelsAdded []string
	drafted     mail.Draft
	msg         mail.Message
}

func (f *fakeDriver) List(context.Context, mail.ListOptions) (mail.Page, error) {
	return mail.Page{Headers: []mail.Header{f.msg.Header}}, nil
}
func (f *fakeDriver) Get(_ context.Context, id string, _ int) (mail.Message, error) {
	if id != f.msg.ID {
		return mail.Message{}, mail.ErrNotFound
	}
	return f.msg, nil
}
func (f *fakeDriver) Thread(context.Context, string, int) ([]mail.Message, error) {
	return []mail.Message{f.msg}, nil
}
func (f *fakeDriver) Search(context.Context, string, mail.ListOptions) (mail.Page, error) {
	return mail.Page{}, nil
}
func (f *fakeDriver) Sent(context.Context, int, time.Time) ([]mail.Message, error) { return nil, nil }
func (f *fakeDriver) SetLabels(_ context.Context, _ string, add, _ []string) error {
	f.labelsAdded = append(f.labelsAdded, add...)
	return nil
}
func (f *fakeDriver) MarkRead(context.Context, string, bool) error { return nil }
func (f *fakeDriver) CreateDraft(_ context.Context, d mail.Draft) (mail.DraftRef, error) {
	f.drafted = d
	return mail.DraftRef{ID: "draft-1"}, nil
}
func (f *fakeDriver) DeleteDraft(context.Context, string) error { return nil }
func (f *fakeDriver) Changes(context.Context, string, time.Duration) ([]mail.Change, string, error) {
	return nil, "1", nil
}
func (f *fakeDriver) Close() error { return nil }

func newTestServer(t *testing.T) (*Server, *fakeDriver) {
	t.Helper()
	drv := &fakeDriver{msg: mail.Message{
		Header: mail.Header{ID: "m1", From: mail.Address{Addr: "alice@example.com"}, Repliable: true},
		Text:   "hello",
	}}
	s := &Server{
		store: fakeStore{subs: map[string]store.Account{"user-1": {Provider: "imap"}}},
		conns: map[string]*conn{"user-1": {drv: drv, used: time.Now()}},
	}
	return s, drv
}

func call(t *testing.T, s *Server, path, sub, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if sub != "" {
		r.Header.Set(SubjectHeader, sub)
	}
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	return w
}

// The single most important property in this package: an app that could name
// its own subject could read anyone's mailbox.
func TestRefusesACallWithNoActingUser(t *testing.T) {
	s, _ := newTestServer(t)
	w := call(t, s, "/tools/list_messages", "", `{}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without a subject, got %d: %s", w.Code, w.Body)
	}
}

func TestUnknownUserIsNotAnError(t *testing.T) {
	s, _ := newTestServer(t)
	w := call(t, s, "/tools/list_messages", "someone-else", `{}`)
	// Not 500 and not 401: the caller is legitimate, they just have not linked
	// a mailbox, and the agent should say so rather than report a fault.
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("want 412 for an unlinked user, got %d: %s", w.Code, w.Body)
	}
}

// The label namespace is a fence: a confused or steered run must not be able
// to reorganise someone's mailbox.
func TestLabelsAreConfinedToTheNamespace(t *testing.T) {
	s, drv := newTestServer(t)

	w := call(t, s, "/tools/set_labels", "user-1", `{"id":"m1","add":["Privasys/needs-reply"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("a namespaced label should be accepted, got %d: %s", w.Code, w.Body)
	}
	if len(drv.labelsAdded) != 1 || drv.labelsAdded[0] != "Privasys/needs-reply" {
		t.Fatalf("label not applied: %v", drv.labelsAdded)
	}

	for _, bad := range []string{"Inbox", "Important", "../escape", "Privasys"} {
		body, _ := json.Marshal(map[string]any{"id": "m1", "add": []string{bad}})
		w := call(t, s, "/tools/set_labels", "user-1", string(body))
		if w.Code == http.StatusOK {
			t.Errorf("label %q should have been refused", bad)
		}
	}
	if len(drv.labelsAdded) != 1 {
		t.Errorf("a refused label reached the driver: %v", drv.labelsAdded)
	}
}

func TestCreateDraftRequiresBoth(t *testing.T) {
	s, drv := newTestServer(t)
	for _, body := range []string{`{}`, `{"reply_to":"m1"}`, `{"body":"hi"}`, `{"reply_to":"m1","body":"   "}`} {
		if w := call(t, s, "/tools/create_draft", "user-1", body); w.Code == http.StatusOK {
			t.Errorf("%s should have been refused", body)
		}
	}
	if drv.drafted.Body != "" {
		t.Error("an incomplete draft reached the driver")
	}
}

// The draft id must not be presented as something to rely on: providers
// recreate drafts under new ids the moment their own UI touches one.
func TestCreateDraftSaysTheIDIsAdvisory(t *testing.T) {
	s, _ := newTestServer(t)
	w := call(t, s, "/tools/create_draft", "user-1", `{"reply_to":"m1","body":"Yes."}`)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	note, _ := got["note"].(string)
	if !strings.Contains(note, "thread") {
		t.Errorf("the response should steer callers to thread-level idempotence, got %q", note)
	}
}

func TestMissingMessageIsA404(t *testing.T) {
	s, _ := newTestServer(t)
	w := call(t, s, "/tools/get_message", "user-1", `{"id":"nope"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body)
	}
}

func TestHealthNeedsNoSubject(t *testing.T) {
	s, _ := newTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("health should be open, got %d", w.Code)
	}
}

// Every tool in the manifest must be routed, or an agent gets a 404 from a
// tool the catalogue told it exists.
func TestManifestToolsAreAllRouted(t *testing.T) {
	s, _ := newTestServer(t)
	for _, name := range []string{
		"list_messages", "get_message", "get_thread", "search", "list_sent",
		"set_labels", "mark_read", "create_draft", "delete_draft", "changes", "account",
	} {
		w := call(t, s, "/tools/"+name, "user-1", `{}`)
		if w.Code == http.StatusNotFound && strings.Contains(w.Body.String(), "404 page not found") {
			t.Errorf("tool %q is in the manifest but has no route", name)
		}
	}
}
