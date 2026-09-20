// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package connector

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/sdk/caller"
	"github.com/Privasys/connectors/sdk/configure"
	"github.com/Privasys/connectors/sdk/credential"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
	"github.com/Privasys/connectors/sdk/mcp"
)

const (
	testApp  = "590ebdc31b63401fbbb822d5f3886c5e"
	otherApp = "0123456789abcdef0123456789abcdef"
	testKind = "thing.box"
)

// account is the credential shape of the connector under test.
type account struct {
	User   string
	Secret string
}

// setup is a Setup that accepts any user with the password "pw" and refuses
// every other, and asks for both fields.
type setup struct {
	creds credential.Store[account]
	keep  map[string]any
}

func (s *setup) Question(context.Context, map[string]any) map[string]any {
	return Elicit("Connect your box.", map[string]any{
		"type": "object",
		"properties": map[string]any{
			"user":     map[string]any{"type": "string", "title": "Address"},
			"password": map[string]any{"type": "string", "title": "App password", "format": "password"},
		},
		"required": []string{"user", "password"},
	}, "password")
}

func (s *setup) Connect(ctx context.Context, sub string, answers map[string]any) (map[string]any, error) {
	user, _ := answers["user"].(string)
	pw, _ := answers["password"].(string)
	if user == "" || pw == "" {
		return nil, &ElicitError{Elicit: s.Question(ctx, answers)}
	}
	if pw != "pw" {
		return nil, Errorf(http.StatusBadGateway, "the box refused these details")
	}
	if err := s.creds.Put(ctx, sub, account{User: user, Secret: pw}); err != nil {
		return nil, err
	}
	return s.keep, nil
}

const manifest = `{"tools":[
 {"name":"configure","role":"config","endpoint":"/configure","description":"x","inputSchema":{"type":"object"}},
 {"name":"read_thing","role":"inference","endpoint":"/tools/read_thing","description":"read","inputSchema":{"type":"object"}},
 {"name":"write_thing","role":"inference","endpoint":"/tools/write_thing","description":"write","inputSchema":{"type":"object"}}
]}`

type rig struct {
	svc      *Service[account]
	creds    *credential.Memory[account]
	mux      *http.ServeMux
	forgot   []string
	forgotAl int
	writes   int
}

func newRig(t *testing.T, requireGrant bool) *rig {
	t.Helper()
	r := &rig{creds: credential.NewMemory[account]()}
	m, err := mcp.Parse([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	r.svc = New(Options[account]{
		Kind: testKind, Resource: "box", Name: "Test Connector", Note: "nothing to do here",
		Credentials:  r.creds,
		RequireGrant: requireGrant,
		Setup:        &setup{creds: r.creds},
		Label:        func(a account) string { return a.User },
		Manifest:     m,
		OnForget:     func(sub string) { r.forgot = append(r.forgot, sub) },
		OnForgetAll:  func() { r.forgotAl++ },
	})
	r.mux = http.NewServeMux()
	r.svc.Mount(r.mux)
	r.svc.Tool(r.mux, "/tools/read_thing", grant.Read, func(_ context.Context, sub string, _ json.RawMessage) (any, error) {
		return map[string]string{"read": sub}, nil
	})
	r.svc.Tool(r.mux, "/tools/write_thing", grant.Write, func(context.Context, string, json.RawMessage) (any, error) {
		r.writes++
		return map[string]bool{"ok": true}, nil
	})
	return r
}

func (r *rig) connect(t *testing.T, sub, user string) {
	t.Helper()
	_ = r.creds.Put(context.Background(), sub, account{User: user, Secret: "pw"})
}

func (r *rig) do(method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.mux.ServeHTTP(w, req)
	return w
}

func asUser(sub, app string) map[string]string {
	h := map[string]string{caller.SubjectHeader: sub}
	if app != "" {
		h[caller.PeerAppHeader] = app
	}
	return h
}

func asHolder(sub string) map[string]string { return map[string]string{holder.RelaySubjectHeader: sub} }

func mintBody(perms []string, setup map[string]any) string {
	req := map[string]any{
		"nonce": "n-1", "subject_app_id": testApp, "kind": testKind,
		"permissions": perms, "expires_unix": time.Now().Add(24 * time.Hour).Unix(),
		"request": map[string]any{"label": "Inbox"},
	}
	if setup != nil {
		req["setup"] = setup
	}
	b, _ := json.Marshal(req)
	return string(b)
}

func (r *rig) mint(t *testing.T, sub string, perms []string) string {
	t.Helper()
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder(sub), mintBody(perms, nil))
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

// credentialNeededBody checks the one refusal every tool gives when the
// holder's credential is not in memory: 403, the two flags, and a sentence
// that sends the agent to request_access WITH ask_again and nowhere else.
func credentialNeededBody(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 without a credential in memory, got %d: %s", w.Code, w.Body)
	}
	var got struct {
		Error            string `json:"error"`
		CredentialNeeded bool   `json:"credential_needed"`
		NeedsHolder      bool   `json:"needs_holder"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("not the JSON refusal: %v (%s)", err, w.Body)
	}
	if !got.CredentialNeeded || !got.NeedsHolder {
		t.Fatalf("both flags must be set: %s", w.Body)
	}
	for _, want := range []string{"not in this service's memory", "on the user's device", "request_access", testKind, "ask_again", "box details"} {
		if !strings.Contains(got.Error, want) {
			t.Errorf("the refusal should say %q: %q", want, got.Error)
		}
	}
	for _, never := range []string{"http://", "https://", "retry", "page"} {
		if strings.Contains(got.Error, never) {
			t.Errorf("the refusal must not say %q: %q", never, got.Error)
		}
	}
}

// ---------------------------------------------------------------- the tools

// The single most important property in this package: an app that could name
// its own subject could read anyone's data.
func TestRefusesACallWithNoActingUser(t *testing.T) {
	r := newRig(t, true)
	for _, path := range []string{"/tools/read_thing", "/api/v1/mcp/tools/read_thing"} {
		if w := r.do(http.MethodPost, path, nil, `{}`); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: want 401 without a subject, got %d: %s", path, w.Code, w.Body)
		}
	}
}

// The order of refusals for a holder is credential first, approval second.
// After a restart both are gone, and what fixes it is the holder's device
// sending the details it kept, which only request_access WITH ask_again
// makes it do. An agent told "ask the user to approve" would request access
// plainly, be told it already has it, and go round again.
func TestNoCredentialIsToldToAskTheDeviceNotToApprove(t *testing.T) {
	r := newRig(t, true)
	w := r.do(http.MethodPost, "/tools/read_thing", asUser("holder-1", otherApp), `{}`)
	credentialNeededBody(t, w)
	if strings.Contains(w.Body.String(), "not approved") {
		t.Fatalf("the approval is not the problem yet: %s", w.Body)
	}
	credentialNeededBody(t, r.do(http.MethodPost, "/api/v1/mcp/tools/read_thing", asUser("holder-1", otherApp), `{}`))
}

func TestUnvouchedAndUnapprovedAppsAreRefused(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "user-1", "u@example.com")
	if w := r.do(http.MethodPost, "/tools/read_thing", asUser("user-1", ""), `{}`); w.Code != http.StatusForbidden {
		t.Fatalf("want 403 with no verified app, got %d: %s", w.Code, w.Body)
	}
	w := r.do(http.MethodPost, "/tools/read_thing", asUser("user-1", testApp), `{}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "not approved") {
		t.Fatalf("want 403 with no capability and the fix, got %d: %s", w.Code, w.Body)
	}
	msg := w.Body.String()
	if !strings.Contains(msg, "request_access for their "+testKind) || !strings.Contains(msg, "Never ask for a password yourself") {
		t.Fatalf("the refusal tells the agent what fixes it and keeps the password out of the chat: %s", msg)
	}
	for _, never := range []string{"http://", "https://", "Drive"} {
		if strings.Contains(msg, never) {
			t.Fatalf("the refusal must not say %q: %q", never, msg)
		}
	}
}

// An expired approval is renewed on the device, and the refusal says so
// without sending anyone to a page.
func TestExpiredGrantIsToldToRenew(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "holder-1", "u@example.com")
	_, _ = r.svc.Grants().Mint(context.Background(), "holder-1", grant.Grant{
		Subject: "app:" + otherApp, Permissions: []grant.Permission{grant.Read},
	})
	w := r.do(http.MethodPost, "/tools/read_thing", asUser("holder-1", otherApp), `{}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "expired") || !strings.Contains(w.Body.String(), "request_access") {
		t.Fatalf("an expired approval is renewed on the device: %d %s", w.Code, w.Body)
	}
}

// The permission split is the point of showing the holder two words rather
// than one: read-only means read-only, at both paths, because they are one
// closure.
func TestReadOnlyCapabilityCannotWriteAtEitherPath(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "user-1", "u@example.com")
	r.mint(t, "user-1", []string{"read"})
	for _, c := range []struct {
		path string
		want int
	}{
		{"/tools/read_thing", http.StatusOK},
		{"/api/v1/mcp/tools/read_thing", http.StatusOK},
		{"/tools/write_thing", http.StatusForbidden},
		{"/api/v1/mcp/tools/write_thing", http.StatusForbidden},
	} {
		if w := r.do(http.MethodPost, c.path, asUser("user-1", testApp), `{}`); w.Code != c.want {
			t.Errorf("%s: want %d, got %d %s", c.path, c.want, w.Code, w.Body)
		}
	}
	if r.writes != 0 {
		t.Fatal("a write reached the handler under a read-only capability")
	}
	r.mint(t, "user-1", []string{"read", "write"})
	if w := r.do(http.MethodPost, "/tools/write_thing", asUser("user-1", testApp), `{}`); w.Code != http.StatusOK || r.writes != 1 {
		t.Fatalf("write should be allowed now: %d %s", w.Code, w.Body)
	}
}

// One holder's approval must not open another holder's data, and one app's
// capability must not serve another app.
func TestCapabilityIsBoundToHolderAndApp(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "user-1", "u@example.com")
	r.connect(t, "user-2", "v@example.com")
	r.mint(t, "user-1", []string{"read"})
	if w := r.do(http.MethodPost, "/tools/read_thing", asUser("user-1", otherApp), `{}`); w.Code != http.StatusForbidden {
		t.Errorf("another app used the capability: %d %s", w.Code, w.Body)
	}
	if w := r.do(http.MethodPost, "/tools/read_thing", asUser("user-2", testApp), `{}`); w.Code != http.StatusForbidden {
		t.Errorf("another holder's data was reached: %d %s", w.Code, w.Body)
	}
}

// Development mode serves every connected holder to every caller, and says
// so in the constructor rather than as a zero value.
func TestRequireGrantOffSkipsOnlyTheCapabilityCheck(t *testing.T) {
	r := newRig(t, false)
	credentialNeededBody(t, r.do(http.MethodPost, "/tools/read_thing", asUser("user-1", ""), `{}`))
	r.connect(t, "user-1", "u@example.com")
	if w := r.do(http.MethodPost, "/tools/read_thing", asUser("user-1", ""), `{}`); w.Code != http.StatusOK {
		t.Fatalf("development mode should serve a connected holder: %d %s", w.Code, w.Body)
	}
	if w := r.do(http.MethodPost, "/tools/read_thing", nil, `{}`); w.Code != http.StatusUnauthorized {
		t.Fatal("even development mode needs an acting user")
	}
}

// A handler's typed error keeps its status; anything else is the provider's
// fault; a credential forgotten under a handler is the standard refusal.
func TestHandlerErrorsMapToStatuses(t *testing.T) {
	r := newRig(t, false)
	r.connect(t, "user-1", "u@example.com")
	r.svc.Tool(r.mux, "/tools/missing", grant.Read, func(context.Context, string, json.RawMessage) (any, error) {
		return nil, Errorf(http.StatusNotFound, "no such thing")
	})
	r.svc.Tool(r.mux, "/tools/broken", grant.Read, func(context.Context, string, json.RawMessage) (any, error) {
		return nil, errors.New("the provider hung up")
	})
	r.svc.Tool(r.mux, "/tools/forgotten", grant.Read, func(context.Context, string, json.RawMessage) (any, error) {
		return nil, credential.ErrNone
	})
	if w := r.do(http.MethodPost, "/tools/missing", asUser("user-1", ""), `{}`); w.Code != http.StatusNotFound {
		t.Errorf("typed error: %d", w.Code)
	}
	if w := r.do(http.MethodPost, "/tools/broken", asUser("user-1", ""), `{}`); w.Code != http.StatusBadGateway {
		t.Errorf("untyped error: %d", w.Code)
	}
	credentialNeededBody(t, r.do(http.MethodPost, "/tools/forgotten", asUser("user-1", ""), `{}`))
}

// ---------------------------------------------------------------- the holder

// The defect this locks out: the holder-facing endpoints once read the acting
// user from X-Privasys-On-Behalf-Of, which the CALLING APP writes. Any app
// that could reach this service could therefore mint itself a capability over
// any account it cared to name, with no wallet screen ever drawn.
func TestActingUserHeaderCannotEstablishAHolder(t *testing.T) {
	r := newRig(t, true)
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/capabilities", mintBody([]string{"read", "write"}, nil)},
		{http.MethodGet, "/v1/apps", ""},
		{http.MethodDelete, "/v1/grants/whatever", ""},
		{http.MethodGet, "/v1/capabilities/setup", ""},
		{http.MethodGet, "/v1/capabilities", ""},
		{http.MethodDelete, "/v1/capabilities/whatever", ""},
	} {
		w := r.do(c.method, c.path, asUser("somebody-elses-box", testApp), c.body)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("an app must not reach %s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
	}
	w := r.do(http.MethodGet, "/v1/apps", asHolder("somebody-elses-box"), "")
	if !strings.Contains(w.Body.String(), `"apps":[]`) {
		t.Fatalf("a capability was minted after all: %s", w.Body)
	}
}

type fakeVerifier struct{ sub string }

func (f fakeVerifier) Verify(context.Context, string) (*holder.Identity, error) {
	return &holder.Identity{Sub: f.sub}, nil
}

// A bearer is only a holder once it VERIFIES; a verified token names the
// holder and only the holder.
func TestBearerHolders(t *testing.T) {
	r := newRig(t, true)
	bearer := map[string]string{"Authorization": "Bearer anything", caller.SubjectHeader: "user-2"}
	if w := r.do(http.MethodGet, "/v1/apps", bearer, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("an unverifiable bearer must not be a holder, got %d", w.Code)
	}
	r.svc.SetVerifier(fakeVerifier{sub: "user-1"})
	r.connect(t, "user-1", "u@example.com")
	r.mint(t, "user-1", []string{"read"})
	w := r.do(http.MethodGet, "/v1/apps", bearer, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), testApp) {
		t.Fatalf("the token's own subject should be the holder: %d %s", w.Code, w.Body)
	}
}

// ---------------------------------------------------------------- the routes

// The wallet reads what this service needs before it draws the approval:
// nothing for a connected holder, the question for one who is not, and never
// anything for an unauthenticated caller or another kind.
func TestSetupSaysWhatTheHolderMustAnswer(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "linked", "u@example.com")
	if w := r.do(http.MethodGet, "/v1/capabilities/setup?kind="+testKind, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	if w := r.do(http.MethodGet, "/v1/capabilities/setup", asHolder("linked"), ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"needed":false`) {
		t.Fatalf("a connected holder needs nothing: %d %s", w.Code, w.Body)
	}
	w := r.do(http.MethodGet, "/v1/capabilities/setup", asHolder("new"), "")
	out := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(out, `"needed":true`) || !strings.Contains(out, `"secrets":["password"]`) || !strings.Contains(out, `"prerequisites":[]`) {
		t.Fatalf("an unconnected holder is asked the question: %d %s", w.Code, out)
	}
	// A verified app relaying for a subject may read it too.
	w = r.do(http.MethodGet, "/v1/capabilities/setup?subject=new", map[string]string{caller.PeerAppHeader: testApp}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("a verified app may read the question for a subject: %d", w.Code)
	}
	if w := r.do(http.MethodGet, "/v1/capabilities/setup?kind=storage.folder", asHolder("new"), ""); w.Code != http.StatusNotFound {
		t.Fatalf("another kind is not this service's: %d", w.Code)
	}
}

// A mint that carries the holder's answers connects first: the provider's
// refusal comes back with its status, missing answers as the question, and a
// mint with no answers from a holder with no credential as the first
// question. Nothing is minted along the way.
func TestMintWithSetupConnectsFirst(t *testing.T) {
	r := newRig(t, true)
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("holder-1"), mintBody([]string{"read"}, nil))
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), `"elicit"`) || !strings.Contains(w.Body.String(), `"App password"`) {
		t.Fatalf("no credential and no answers: want the question, got %d %s", w.Code, w.Body)
	}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("holder-1"), mintBody([]string{"read"}, map[string]any{"user": "me@example.org"}))
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("half the answers: want one more question, got %d %s", w.Code, w.Body)
	}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("holder-1"), mintBody([]string{"read"}, map[string]any{"user": "me@example.org", "password": "wrong"}))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "refused these details") {
		t.Fatalf("the provider's refusal: %d %s", w.Code, w.Body)
	}
	if _, err := r.creds.Get(context.Background(), "holder-1"); !errors.Is(err, credential.ErrNone) {
		t.Fatal("an unproven credential was kept")
	}
	if w := r.do(http.MethodGet, "/v1/apps", asHolder("holder-1"), ""); !strings.Contains(w.Body.String(), `"apps":[]`) {
		t.Fatalf("something was minted on the way: %s", w.Body)
	}
}

// The whole flow on one tap: the answers are proved, kept in memory, and the
// capability is minted over them. The response says which account and
// nothing else about it, and carries keep only when the connector has
// something for the wallet to hold.
func TestMintWithSetupKeepsTheCredentialAndMints(t *testing.T) {
	r := newRig(t, true)
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("holder-1"), mintBody([]string{"read"}, map[string]any{"user": "me@example.org", "password": "pw"}))
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
	if got.ServiceResult["account"] != "me@example.org" || got.ServiceResult["kind"] != testKind {
		t.Fatalf("service_result should name the account and the kind: %s", w.Body)
	}
	if got.Keep != nil {
		t.Fatalf("nothing to keep, so no keep: %s", w.Body)
	}
	if strings.Contains(w.Body.String(), `"pw"`) {
		t.Fatal("the password was echoed")
	}
	if w := r.do(http.MethodPost, "/tools/read_thing", asUser("holder-1", testApp), `{}`); w.Code != http.StatusOK {
		t.Fatalf("the minted capability should serve: %d %s", w.Code, w.Body)
	}

	// A connector with something for the wallet to keep (a refresh token)
	// hands it back beside the usual fields.
	r.svc.o.Setup = &setup{creds: r.creds, keep: map[string]any{"refresh_token": "rt-1"}}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("holder-2"), mintBody([]string{"read"}, map[string]any{"user": "x@example.org", "password": "pw"}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"keep":{"refresh_token":"rt-1"}`) {
		t.Fatalf("keep should ride the mint: %d %s", w.Code, w.Body)
	}
}

// S4 at the HTTP boundary: the holder is whoever authenticated, and a request
// that tries to name one is refused outright; so is another kind.
func TestMintRefusesBadRequests(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "user-1", "u@example.com")
	for _, field := range []string{"user", "account", "mailbox", "calendar", "tenant"} {
		body, _ := json.Marshal(map[string]any{
			"nonce": "n", "subject_app_id": testApp, "kind": testKind,
			"permissions": []string{"read"}, "expires_unix": time.Now().Add(time.Hour).Unix(),
			"request": map[string]any{field: "victim@example.com"},
		})
		if w := r.do(http.MethodPost, "/v1/capabilities", asHolder("user-1"), string(body)); w.Code != http.StatusBadRequest {
			t.Errorf("a request naming %q should be refused, got %d: %s", field, w.Code, w.Body)
		}
	}
	body, _ := json.Marshal(map[string]any{
		"nonce": "n", "subject_app_id": testApp, "kind": "other.kind",
		"permissions": []string{"read"}, "expires_unix": time.Now().Add(time.Hour).Unix(),
	})
	if w := r.do(http.MethodPost, "/v1/capabilities", asHolder("user-1"), string(body)); w.Code != http.StatusBadRequest {
		t.Errorf("another kind should be refused, got %d", w.Code)
	}
	if w := r.do(http.MethodPost, "/v1/capabilities", asHolder("user-1"), "not json"); w.Code != http.StatusBadRequest {
		t.Errorf("malformed: %d", w.Code)
	}
}

func listCaps(t *testing.T, r *rig, sub string) (int, []View) {
	t.Helper()
	w := r.do(http.MethodGet, "/v1/capabilities", asHolder(sub), "")
	var out struct {
		Capabilities []View `json:"capabilities"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out.Capabilities
}

func TestHolderListsCapabilitiesInTheSharedShape(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "user-1", "u@example.com")
	id := r.mint(t, "user-1", []string{"read", "write"})
	code, caps := listCaps(t, r, "user-1")
	if code != http.StatusOK || len(caps) != 1 {
		t.Fatalf("list = %d, %d capabilities", code, len(caps))
	}
	got := caps[0]
	if got.CapabilityID != id || got.Kind != testKind || got.ResourceLabel != "u@example.com" || len(got.Permissions) != 2 || !strings.HasSuffix(got.SubjectAppID, testApp) {
		t.Fatalf("unexpected view: %+v", got)
	}
	if _, caps := listCaps(t, r, "user-2"); len(caps) != 0 {
		t.Fatalf("another holder saw %d capabilities", len(caps))
	}
	// The older list, and a null-free empty one for a holder with nothing.
	if w := r.do(http.MethodGet, "/v1/apps", asHolder("user-1"), ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), testApp) {
		t.Fatalf("/v1/apps: %d %s", w.Code, w.Body)
	}
	if w := r.do(http.MethodGet, "/v1/apps", asHolder("user-2"), ""); !strings.Contains(w.Body.String(), `"apps":[]`) {
		t.Fatalf("/v1/apps for another holder: %s", w.Body)
	}
}

// The promise the wallet makes when it says the service destroys its copy:
// with the last capability go the credential and what was opened with it. A
// second revoke of the same id is 410; someone else's id is 404 and touches
// nothing; one of two capabilities keeps the credential.
func TestRevokeIsTheRealThing(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "user-1", "u@example.com")
	first := r.mint(t, "user-1", []string{"read"})
	second, err := r.svc.Grants().Mint(context.Background(), "user-1", grant.Grant{
		Subject: "app:" + otherApp, Permissions: []grant.Permission{grant.Read}, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	if w := r.do(http.MethodDelete, "/v1/capabilities/"+first, asHolder("user-2"), ""); w.Code != http.StatusNotFound {
		t.Fatalf("cross-holder revoke = %d, want 404", w.Code)
	}
	if w := r.do(http.MethodDelete, "/v1/capabilities/"+first, asHolder("user-1"), ""); w.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204", w.Code)
	}
	if _, err := r.creds.Get(context.Background(), "user-1"); err != nil {
		t.Fatal("the credential was destroyed while another capability was still live")
	}
	if len(r.forgot) != 0 {
		t.Fatal("the connector was told to forget while another capability was still live")
	}
	if w := r.do(http.MethodDelete, "/v1/capabilities/"+first, asHolder("user-1"), ""); w.Code != http.StatusGone {
		t.Fatalf("second revoke = %d, want 410", w.Code)
	}
	if w := r.do(http.MethodPost, "/tools/read_thing", asUser("user-1", testApp), `{}`); w.Code != http.StatusForbidden {
		t.Fatalf("access survived revoke: %d %s", w.Code, w.Body)
	}

	if w := r.do(http.MethodDelete, "/v1/grants/"+second.ID, asHolder("user-1"), ""); w.Code != http.StatusOK {
		t.Fatalf("older revoke = %d, want 200", w.Code)
	}
	if _, err := r.creds.Get(context.Background(), "user-1"); !errors.Is(err, credential.ErrNone) {
		t.Fatal("the last capability went and the credential outlived it")
	}
	if len(r.forgot) != 1 || r.forgot[0] != "user-1" {
		t.Fatalf("the connector should have been told to close what it opened: %v", r.forgot)
	}
	if _, caps := listCaps(t, r, "user-1"); len(caps) != 0 {
		t.Fatalf("still listed after revoke: %v", caps)
	}
	credentialNeededBody(t, r.do(http.MethodPost, "/tools/read_thing", asUser("user-1", testApp), `{}`))
}

func TestCapabilityEndpointsNeedAHolder(t *testing.T) {
	r := newRig(t, true)
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/v1/capabilities"},
		{http.MethodGet, "/v1/apps"},
		{http.MethodDelete, "/v1/grants/abc"},
		{http.MethodGet, "/v1/capabilities"},
		{http.MethodDelete, "/v1/capabilities/abc"},
	} {
		if w := r.do(c.method, c.path, nil, `{}`); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a holder should be 401, got %d", c.method, c.path, w.Code)
		}
	}
}

// ---------------------------------------------------------------- the rest

func TestRootHealthAndCatalogue(t *testing.T) {
	r := newRig(t, true)
	w := r.do(http.MethodGet, "/", nil, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Test Connector") {
		t.Fatalf("root: %d %s", w.Code, w.Body)
	}
	for _, never := range []string{"<form", "<input", "password", "<script"} {
		if strings.Contains(strings.ToLower(w.Body.String()), never) {
			t.Errorf("the root must not be a place to type a secret (%q)", never)
		}
	}
	if w := r.do(http.MethodGet, "/nothing-here", nil, ""); w.Code != http.StatusNotFound {
		t.Fatalf("an unknown path is still a 404, got %d", w.Code)
	}
	if w := r.do(http.MethodGet, "/health", nil, ""); w.Code != http.StatusOK {
		t.Fatal("health should be open")
	}
	w = r.do(http.MethodGet, "/api/v1/mcp/tools", nil, "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"configure"`) || !strings.Contains(w.Body.String(), "read_thing") {
		t.Fatalf("catalogue: %d %s", w.Code, w.Body)
	}
	// configure is not reachable at the agent's path either. 405 rather than
	// 404 because the root's GET matches the path for a different method;
	// what must never happen is a 2xx.
	w = r.do(http.MethodPost, "/api/v1/mcp/tools/configure", asUser("user-1", testApp), `{"idp_issuer":"https://attacker.example"}`)
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("configure must not be reachable at the agent's path, got %d", w.Code)
	}
}

// ---------------------------------------------------------------- configure

type settings struct {
	IdpIssuer   string `json:"idp_issuer,omitempty"`
	IdpAudience string `json:"idp_audience,omitempty"`
}

func (s settings) Validate() error { return configure.ValidateIssuer(s.IdpIssuer) }
func (s settings) Normalised() settings {
	out := settings{IdpIssuer: strings.TrimRight(strings.TrimSpace(s.IdpIssuer), "/"), IdpAudience: strings.TrimSpace(s.IdpAudience)}
	if out.IdpIssuer == "" {
		out.IdpIssuer = configure.DefaultIdpIssuer
	}
	if out.IdpAudience == "" {
		out.IdpAudience = configure.DefaultIdpAudience
	}
	return out
}
func (s settings) Identity() (string, string) { return s.IdpIssuer, s.IdpAudience }
func (s settings) DigestFields() []string     { return []string{s.IdpIssuer, s.IdpAudience} }
func (s settings) Public() map[string]any {
	return map[string]any{"idp_issuer": s.IdpIssuer, "idp_audience": s.IdpAudience}
}

// Everything is held at 503 before configure; the same settings again keep
// what is in memory; a different identity root forgets everyone, and the
// bearer verifier follows the issuer.
func TestConfigureGatesAndReconfigureForgets(t *testing.T) {
	r := newRig(t, true)
	gate := configure.NewGate(filepath.Join(t.TempDir(), "config.json"), settings{}, false)
	r.svc.o.Config = gate
	r.mux = http.NewServeMux()
	r.svc.Mount(r.mux)
	r.svc.Tool(r.mux, "/tools/read_thing", grant.Read, func(context.Context, string, json.RawMessage) (any, error) { return "ok", nil })

	if w := r.do(http.MethodPost, "/tools/read_thing", asUser("holder-1", testApp), `{}`); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("every tool is held at 503 before configure, got %d", w.Code)
	}
	if w := r.do(http.MethodPost, "/v1/capabilities", asHolder("holder-1"), mintBody([]string{"read"}, nil)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("the mint is held at 503 before configure, got %d", w.Code)
	}
	if w := r.do(http.MethodGet, "/v1/capabilities/setup", asHolder("holder-1"), ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("setup is held at 503 before configure, got %d", w.Code)
	}
	if w := r.do(http.MethodPost, "/configure", nil, `{}`); w.Code != http.StatusOK {
		t.Fatalf("configure: %d %s", w.Code, w.Body)
	}
	if r.svc.Verifier() == nil {
		t.Fatal("configure should install a verifier for the issuer")
	}
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("holder-1"), mintBody([]string{"read"}, map[string]any{"user": "me@example.org", "password": "pw"}))
	if w.Code != http.StatusOK {
		t.Fatalf("mint: %d %s", w.Code, w.Body)
	}

	if w := r.do(http.MethodPost, "/configure", nil, `{}`); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	if _, err := r.creds.Get(context.Background(), "holder-1"); err != nil {
		t.Fatalf("the same settings again must keep what is in memory: %v", err)
	}
	if r.forgotAl != 0 {
		t.Fatal("the same settings again told the connector to forget")
	}

	if w := r.do(http.MethodPost, "/configure", nil, `{"idp_issuer":"https://other.example"}`); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	if _, err := r.creds.Get(context.Background(), "holder-1"); err == nil {
		t.Fatal("a credential approved under the old issuer survived the new one")
	}
	if _, err := r.svc.Grants().Find(context.Background(), "holder-1", "app:"+testApp); err == nil {
		t.Fatal("a capability approved under the old issuer survived the new one")
	}
	if r.forgotAl != 1 {
		t.Fatal("the connector should have been told to close everything")
	}
	credentialNeededBody(t, r.do(http.MethodPost, "/tools/read_thing", asUser("holder-1", testApp), `{}`))

	// And the digest is published now that there is a configuration.
	w = r.do(http.MethodGet, "/.well-known/attestation-extensions", nil, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), configure.OIDConfigDigest) {
		t.Fatalf("extensions: %d %s", w.Code, w.Body)
	}
}

// Close is what a shutdown does, and it leaves nothing.
func TestCloseForgetsEverything(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "holder-1", "u@example.com")
	r.mint(t, "holder-1", []string{"read"})
	if err := r.svc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.creds.Get(context.Background(), "holder-1"); err == nil {
		t.Fatal("Close left a credential behind")
	}
	if _, err := r.svc.Grants().Find(context.Background(), "holder-1", "app:"+testApp); err == nil {
		t.Fatal("Close left a capability behind")
	}
	if r.forgotAl != 1 {
		t.Fatal("Close should tell the connector to close everything")
	}
}
