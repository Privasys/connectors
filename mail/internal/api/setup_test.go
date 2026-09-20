// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/mail/internal/discover"
	"github.com/Privasys/connectors/mail/internal/imapdrv"
	"github.com/Privasys/connectors/mail/internal/mail"
	"github.com/Privasys/connectors/mail/internal/store"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/provider"
)

// A test must never reach the network to find a server.
func offlineDiscovery(t *testing.T) {
	t.Helper()
	prev := discover.Default
	discover.Default = &discover.Resolver{}
	t.Cleanup(func() { discover.Default = prev })
}

// offlineProvider answers who hosts an address from the well-known table
// alone, never from DNS.
func offlineProvider(s *Server) { s.who = &provider.Resolver{} }

// acceptingMailbox stands in for every mailbox: it opens for whatever it is
// offered and records the config it was opened with, so a test can see how
// a credential was dialled without dialling anything.
func acceptingMailbox(s *Server) *[]imapdrv.Config {
	var opened []imapdrv.Config
	s.open = func(ctx context.Context, cfg imapdrv.Config) (mail.Driver, error) {
		if cfg.Token != nil {
			// A sign-in is dialled with the token the source hands over,
			// which is what a test wants to see.
			tok, err := cfg.Token(ctx)
			if err != nil {
				return nil, err
			}
			cfg.Password = "bearer:" + tok
		}
		opened = append(opened, cfg)
		return &fakeDriver{}, nil
	}
	return &opened
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

// freshServer is what a restart leaves: empty stores, and a mailbox that
// accepts whatever it is offered so the test never dials anything.
func freshServer(t *testing.T) *Server {
	t.Helper()
	s := New(store.NewMemory(), grant.NewMemory(), true)
	offlineProvider(s)
	acceptingMailbox(s)
	return s
}

// The wallet reads what this service needs before it draws the approval:
// nothing for a connected holder, the address alone for one who is not
// (the password or the sign-in button come at the second step, once the
// address says which), and never anything for an unauthenticated caller.
// There is nothing to approve first: this service asks for no folder.
func TestSetupSaysWhatTheHolderMustAnswer(t *testing.T) {
	s := New(fakeStore{subs: map[string]store.Account{"linked": {Provider: "imap", User: "u@example.com"}}}, grant.NewMemory(), true)
	offlineProvider(s)
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
	if w.Code != http.StatusOK || !strings.Contains(out, `"needed":true`) || !strings.Contains(out, `"Email address"`) {
		t.Fatalf("an unconnected holder is asked for the address: %d %s", w.Code, out)
	}
	if strings.Contains(out, `"password"`) || strings.Contains(out, "x-privasys-oauth") {
		t.Fatalf("the address comes first, alone; the credential step depends on it: %s", out)
	}
	var parsed struct {
		Message       string           `json:"message"`
		Prerequisites []map[string]any `json:"prerequisites"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &parsed)
	if len(parsed.Prerequisites) != 0 {
		t.Fatalf("nothing is approved before the mailbox: %s", out)
	}
	if strings.Contains(parsed.Message, "Drive") || !strings.Contains(parsed.Message, "stores nothing") {
		t.Fatalf("the message must say the details are kept by the device and stored by nothing: %q", parsed.Message)
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

// The second step is decided by the address, and by nothing the holder
// picks: a provider we reach directly is asked for an app password; an
// address at Google or Microsoft (their own domains, or a domain whose MX is
// theirs) is never offered a password, because both are retiring passwords
// over IMAP. A domain whose MX cannot be read is "somewhere else", which
// means the password path: the honest answer for a domain we could not read.
func TestSecondStepIsDecidedByTheAddress(t *testing.T) {
	s := freshServer(t)
	s.who = &provider.Resolver{LookupMX: func(_ context.Context, domain string) ([]*net.MX, error) {
		switch domain {
		case "workspace.example":
			return []*net.MX{{Host: "aspmx.l.google.com."}}, nil
		case "tenant.example":
			return []*net.MX{{Host: "tenant-example.mail.protection.outlook.com."}}, nil
		}
		return nil, errors.New("no such domain")
	}}
	second := func(user string) string {
		t.Helper()
		w := mintWith(t, s, "holder-1", map[string]any{"user": user})
		if w.Code != http.StatusPreconditionRequired {
			t.Fatalf("%s: the address alone is one more question, got %d %s", user, w.Code, w.Body)
		}
		return w.Body.String()
	}
	for _, user := range []string{"me@example.org", "me@unreadable.example", "me@fastmail.com"} {
		if out := second(user); !strings.Contains(out, `"App password"`) || !strings.Contains(out, `"secrets":["password"]`) {
			t.Fatalf("%s is reached directly, so the second step is the password: %s", user, out)
		}
	}
	for _, user := range []string{"me@gmail.com", "me@workspace.example", "me@outlook.com", "me@tenant.example"} {
		out := second(user)
		if strings.Contains(out, `"password"`) || strings.Contains(out, "App password") {
			t.Fatalf("%s is at Google or Microsoft and must never be offered a password: %s", user, out)
		}
		if !strings.Contains(out, user) {
			t.Fatalf("the second step names the address it is for: %s", out)
		}
	}
	// Without a sign-in client configured for the provider, the 428 says so
	// and offers nothing: no button, no password fallback.
	if out := second("me@gmail.com"); !strings.Contains(out, "no Google sign-in configured") || strings.Contains(out, "x-privasys-oauth") {
		t.Fatalf("a Google address with no Google client is the honest 428: %s", out)
	}
	if out := second("me@hotmail.fr"); !strings.Contains(out, "no Microsoft sign-in configured") || strings.Contains(out, "x-privasys-oauth") {
		t.Fatalf("a Microsoft address with no Microsoft client is the honest 428: %s", out)
	}
	// An address without a domain is the first question again.
	if out := second("not-an-address"); !strings.Contains(out, `"Email address"`) || strings.Contains(out, "App password") {
		t.Fatalf("no domain, no second step: %s", out)
	}
}

// A mint that carries the holder's answers connects the mailbox first: the
// provider's refusal comes back as a 502 the wallet shows beside the fields,
// a server nobody can find as a 428 with one more question, and a mint with
// no answers from a holder with no mailbox as the first question.
func TestMintWithSetupConnectsFirst(t *testing.T) {
	offlineDiscovery(t)
	st := store.NewMemory()
	s := New(st, grant.NewMemory(), true)
	offlineProvider(s)

	w := mintWith(t, s, "holder-1", nil)
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), `"Email address"`) || strings.Contains(w.Body.String(), `"App password"`) {
		t.Fatalf("no mailbox and no answers: want the address question, got %d %s", w.Code, w.Body)
	}

	w = mintWith(t, s, "holder-1", map[string]any{"user": "me@example.org", "password": "pw", "host": "127.0.0.1:1"})
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "refused these details") {
		t.Fatalf("an unreachable named server is the provider's refusal: %d %s", w.Code, w.Body)
	}
	if _, err := st.Get(context.Background(), "holder-1"); !errors.Is(err, store.ErrNoAccount) {
		t.Fatal("an unproven credential was kept")
	}

	w = mintWith(t, s, "holder-1", map[string]any{"user": "me@nowhere.invalid", "password": "pw"})
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), `"IMAP server"`) || !strings.Contains(w.Body.String(), "imap.nowhere.invalid:993") {
		t.Fatalf("a server nobody can find is one more question, naming what was tried: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "pw") {
		t.Fatal("the password was echoed")
	}
}

// The whole flow on one tap: the answers are proved, kept in memory, and the
// capability is minted over them. The response says which mailbox and
// nothing else about it, and hands the wallet nothing to keep for this
// service, because there is nothing.
func TestMintWithSetupKeepsTheCredentialAndMints(t *testing.T) {
	s := freshServer(t)
	w := mintWith(t, s, "holder-1", map[string]any{"user": "me@example.org", "password": "pw", "host": "imap.example.org"})
	if w.Code != http.StatusOK {
		t.Fatalf("want a mint, got %d %s", w.Code, w.Body)
	}
	var got struct {
		CapabilityID  string            `json:"capability_id"`
		Nonce         string            `json:"nonce"`
		ExpiresUnix   int64             `json:"expires_unix"`
		ServiceResult map[string]string `json:"service_result"`
		Keep          *json.RawMessage  `json:"keep"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.CapabilityID == "" || got.Nonce != "n-1" || got.ExpiresUnix == 0 {
		t.Fatalf("the mint is incomplete: %s", w.Body)
	}
	if got.ServiceResult["account"] != "me@example.org" || got.ServiceResult["kind"] != mail.Kind {
		t.Fatalf("service_result should name the mailbox and the kind: %s", w.Body)
	}
	if got.Keep != nil {
		t.Fatalf("an IMAP credential is the holder's own answer, so there is nothing for the wallet to keep: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "pw") {
		t.Fatal("the password was echoed")
	}

	acct, err := s.credStore().Get(context.Background(), "holder-1")
	if err != nil {
		t.Fatalf("the credential is not in memory after the mint: %v", err)
	}
	if acct.Host != "imap.example.org:993" || acct.User != "me@example.org" || acct.Secret != "pw" {
		t.Fatalf("kept the wrong thing: %+v", acct)
	}
	// And the tools now serve this app for this holder: the mailbox opens
	// (a fake, here) under the capability just minted.
	s.mu.Lock()
	s.conns["holder-1"] = &conn{drv: &fakeDriver{}, used: time.Now()}
	s.mu.Unlock()
	if w := callAs(t, s, "/tools/list_messages", "holder-1", testApp, `{}`); w.Code != http.StatusOK {
		t.Fatalf("the minted capability should serve: %d %s", w.Code, w.Body)
	}
}

// A restart is a fresh process with empty stores, and the design accepts what
// it costs: the wallet's next mint is answered with the question (it sends
// the answers it kept without asking anyone), and until then every tool call
// sends the agent to the holder's device with ask_again.
func TestRestartForgetsAndAsksAgain(t *testing.T) {
	before := freshServer(t)
	w := mintWith(t, before, "holder-1", map[string]any{"user": "me@example.org", "password": "pw", "host": "imap.example.org"})
	if w.Code != http.StatusOK {
		t.Fatalf("setup mint before the restart: %d %s", w.Code, w.Body)
	}

	after := freshServer(t) // the same deployment, restarted
	w = mintWith(t, after, "holder-1", nil)
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), `"elicit"`) {
		t.Fatalf("a mint without setup after a restart is answered with the question: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "capability_id") {
		t.Fatal("nothing may be minted over a forgotten credential")
	}
	credentialNeededBody(t, callAs(t, after, "/tools/list_messages", "holder-1", testApp, `{}`))
	credentialNeededBody(t, callAs(t, after, "/tools/changes", "holder-1", testApp, `{}`))

	// The wallet re-supplies the answers with the next mint, and everything
	// is back: credential and capability in the same call.
	w = mintWith(t, after, "holder-1", map[string]any{"user": "me@example.org", "password": "pw", "host": "imap.example.org"})
	if w.Code != http.StatusOK {
		t.Fatalf("the re-supplied answers should mint again: %d %s", w.Code, w.Body)
	}
	if _, err := after.credStore().Get(context.Background(), "holder-1"); err != nil {
		t.Fatalf("the credential is not back in memory: %v", err)
	}
	if _, err := after.grantStore().Find(context.Background(), "holder-1", "app:"+testApp); err != nil {
		t.Fatalf("the capability is not back: %v", err)
	}
}

func TestDomainsAreNormalised(t *testing.T) {
	got := cleanDomains([]string{" @Example.COM ", "", "  ", "example.co.uk"})
	if len(got) != 2 || got[0] != "example.com" || got[1] != "example.co.uk" {
		t.Fatalf("domains not normalised: %#v", got)
	}
}
