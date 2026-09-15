// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/connectors/mail/internal/grant"
	"github.com/Privasys/connectors/mail/internal/store"
)

func connectRequest(body string, elicited bool) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://mail-connector.apps.test.privasys.org/tools/connect_mailbox", strings.NewReader(body))
	r.Header.Set(SubjectHeader, "holder-1")
	r.Header.Set(PeerAppHeader, "0123456789abcdef0123456789abcdef")
	r.Header.Set(PeerVerifiedHeader, "true")
	if elicited {
		r.Header.Set(ElicitationHeader, "elicit-0123")
	}
	return r
}

// A credential is accepted only as the holder's answer to this service's own
// question. 2026-09-15: the model asked for the app password with its
// question tool and passed it as arguments, so it sat in the session record;
// the tool now declares no arguments and drops any that arrive unmarked.
func TestConnectMailboxAsksTheHolderUnlessTheValuesAreTheirAnswers(t *testing.T) {
	s := New(fakeStore{subs: map[string]store.Account{}}, grant.NewMemory(), true)

	for _, body := range []string{``, `{}`, `{"user":"me@example.com","password":"typed-by-the-model"}`} {
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, connectRequest(body, false))
		if w.Code != http.StatusPreconditionRequired {
			t.Fatalf("body %q without the elicitation mark: want 428, got %d %s", body, w.Code, w.Body)
		}
		out := w.Body.String()
		if !strings.Contains(out, `"elicit"`) || !strings.Contains(out, `"format":"password"`) || strings.Contains(out, "typed-by-the-model") {
			t.Fatalf("the answer must be the question, with the secret marked and nothing echoed: %s", out)
		}
	}

	// The holder's answers, marked by the harness, go on to be proved: the
	// probe dials the named host, which here refuses, so the call fails at
	// the mailbox and not before it.
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, connectRequest(`{"user":"me@example.com","password":"s3cret","host":"127.0.0.1:1"}`, true))
	if w.Code == http.StatusPreconditionRequired {
		t.Fatalf("the holder's own answers must not be asked for again: %d %s", w.Code, w.Body)
	}
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "refused these details") {
		t.Fatalf("want the credential proved against the mailbox, got %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "s3cret") {
		t.Fatal("the password was echoed")
	}
}
