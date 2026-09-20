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

	"github.com/Privasys/connectors/meetings/internal/archive"
	"github.com/Privasys/connectors/meetings/internal/meet"
	"github.com/Privasys/connectors/meetings/internal/store"
	"github.com/Privasys/connectors/meetings/internal/teamsdrv"
	"github.com/Privasys/connectors/meetings/internal/zoomdrv"
	"github.com/Privasys/connectors/sdk/caller"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
	"github.com/Privasys/connectors/sdk/provider"
	"github.com/Privasys/connectors/sdk/vtt"
)

const testApp = "590ebdc31b63401fbbb822d5f3886c5e"

var now = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

const sampleVTT = "WEBVTT\n\n00:00:00.500 --> 00:00:02.000\nAlice: Hello, your verification code is 483920\n\n00:00:02.100 --> 00:00:04.000\nBob: Hi Alice\n"

// fakeDriver is a provider with two meetings: one transcribed a day ago,
// one recorded without a transcript.
type fakeDriver struct {
	provider string
	meetings []meet.Meeting
	tokens   []string
	closed   bool
}

func newFakeDriver(provider string, token func(context.Context) (string, error)) (*fakeDriver, error) {
	tok, err := token(context.Background())
	if err != nil {
		return nil, err
	}
	if tok == "bad" {
		return nil, meet.ErrLogin
	}
	f := &fakeDriver{provider: provider, tokens: []string{tok}}
	f.meetings = []meet.Meeting{
		{ID: "m-1", Provider: provider, Title: "Weekly sync", Start: now.Add(-25 * time.Hour), End: now.Add(-24 * time.Hour),
			Organiser: &meet.Person{Address: "host@example.org"}, HasTranscript: true, HasRecording: true, TranscriptAt: now.Add(-23 * time.Hour)},
		{ID: "m-2", Provider: provider, Title: "No transcript", Start: now.Add(-3 * time.Hour), End: now.Add(-2 * time.Hour), HasRecording: true},
	}
	return f, nil
}

func (f *fakeDriver) Meetings(_ context.Context, from, to time.Time) ([]meet.Meeting, error) {
	var out []meet.Meeting
	for _, m := range f.meetings {
		if !m.Start.Before(from) && m.Start.Before(to) {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *fakeDriver) Transcript(_ context.Context, id string) (meet.Transcript, error) {
	for _, m := range f.meetings {
		if m.ID != id {
			continue
		}
		if !m.HasTranscript {
			return meet.Transcript{}, meet.ErrNoTranscript
		}
		return meet.Transcript{Meeting: m, VTT: []byte(sampleVTT)}, nil
	}
	return meet.Transcript{}, meet.ErrNotFound
}

func (f *fakeDriver) Close() error { f.closed = true; return nil }

// fakeArchive records saves and answers as told.
type fakeArchive struct {
	approved bool
	saves    []meet.Meeting
}

func (a *fakeArchive) Status(context.Context, string) (archive.Status, error) {
	return archive.Status{Configured: true, Approved: a.approved, Path: "AppData/Meeting transcripts"}, nil
}
func (a *fakeArchive) Prerequisite(context.Context, string) []map[string]string {
	if a.approved {
		return nil
	}
	return []map[string]string{{"app_host": "meetings.apps.example", "nonce": "nonce-1"}}
}
func (a *fakeArchive) Save(_ context.Context, _ string, m meet.Meeting, t *vtt.Transcript, raw []byte) (archive.Saved, error) {
	if !a.approved {
		return archive.Saved{}, &archive.NeedsFolder{Reason: "the user has not approved the Meeting transcripts folder"}
	}
	a.saves = append(a.saves, m)
	return archive.Saved{Folder: "AppData/Meeting transcripts", MarkdownPath: "AppData/Meeting transcripts/" + archive.Stem(m) + ".md",
		Indexing: "Drive lets only the user make an app's folder searchable"}, nil
}

type rig struct {
	s       *Server
	drivers []*fakeDriver
	archive *fakeArchive
	// identity is the address the fake providers say signed in.
	identity string
}

// fakeMX is the DNS the tests see: tenant.example at Microsoft 365, and
// every other domain hosted elsewhere or unknown.
func fakeMX(_ context.Context, domain string) ([]*net.MX, error) {
	if domain == "tenant.example" {
		return []*net.MX{{Host: "tenant-example.mail.protection.outlook.com."}}, nil
	}
	return nil, errors.New("no such domain")
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{s: New(store.NewMemory(), grant.NewMemory(), true), archive: &fakeArchive{}, identity: "me@example.org"}
	r.s.now = func() time.Time { return now }
	r.s.who = &provider.Resolver{LookupMX: fakeMX}
	r.s.SetArchive(r.archive)
	r.s.openZoom = func(_ context.Context, cfg zoomdrv.Config) (meet.Driver, meet.Profile, error) {
		d, err := newFakeDriver(meet.ProviderZoom, cfg.Token)
		if err != nil {
			return nil, meet.Profile{}, err
		}
		r.drivers = append(r.drivers, d)
		return d, meet.Profile{Address: r.identity, Name: "Me"}, nil
	}
	r.s.openTeams = func(_ context.Context, cfg teamsdrv.Config) (meet.Driver, meet.Profile, error) {
		d, err := newFakeDriver(meet.ProviderTeams, cfg.Token)
		if err != nil {
			return nil, meet.Profile{}, err
		}
		r.drivers = append(r.drivers, d)
		return d, meet.Profile{Address: r.identity, Name: "Me"}, nil
	}
	return r
}

func (r *rig) do(method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Host = "meetings.apps.example"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.s.Routes().ServeHTTP(w, req)
	return w
}

func asUser(sub string) map[string]string {
	return map[string]string{caller.SubjectHeader: sub, caller.PeerAppHeader: testApp}
}

func asHolder(sub string) map[string]string { return map[string]string{holder.RelaySubjectHeader: sub} }

func mintBody(setup map[string]any) string {
	req := map[string]any{
		"nonce": "n-1", "subject_app_id": testApp, "kind": meet.Kind,
		"permissions": []string{"read"}, "expires_unix": time.Now().Add(24 * time.Hour).Unix(),
	}
	if setup != nil {
		req["setup"] = setup
	}
	b, _ := json.Marshal(req)
	return string(b)
}

// connect puts a proven account in memory and mints, the way the wallet
// does once it has the tokens.
func (r *rig) connect(t *testing.T, sub, provider string) {
	t.Helper()
	if err := r.s.credStore().Put(context.Background(), sub, store.Account{
		Provider: provider, User: "me@example.org", LinkedAt: now, RefreshToken: "rt-1", AccessToken: "at-1", Expiry: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder(sub), mintBody(nil))
	if w.Code != http.StatusOK {
		t.Fatalf("mint: %d %s", w.Code, w.Body)
	}
}

func (r *rig) call(t *testing.T, sub, tool, body string) *httptest.ResponseRecorder {
	t.Helper()
	return r.do(http.MethodPost, "/tools/"+tool, asUser(sub), body)
}

func decode(t *testing.T, w *httptest.ResponseRecorder, into any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), into); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, w.Body)
	}
}

// ---------------------------------------------------------------- tools

func TestListMeetingsDefaultsToTheLastWeek(t *testing.T) {
	r := newRig(t)
	r.connect(t, "u1", meet.ProviderZoom)
	w := r.call(t, "u1", "list_meetings", `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var out struct {
		Meetings []meet.Meeting `json:"meetings"`
		From, To time.Time
	}
	decode(t, w, &out)
	if len(out.Meetings) != 2 || !out.Meetings[0].HasTranscript || out.Meetings[1].HasTranscript {
		t.Errorf("meetings: %+v", out.Meetings)
	}
	if !out.To.Equal(now) || !out.From.Equal(now.Add(-7*24*time.Hour)) {
		t.Errorf("window: %v %v", out.From, out.To)
	}
	if w := r.call(t, "u1", "list_meetings", `{"from":"2026-01-01","to":"2026-09-01"}`); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "longer than 62 days") {
		t.Errorf("a long window: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "list_meetings", `{"from":"2026-09-14"}`); w.Code != http.StatusOK {
		t.Errorf("from alone: %d %s", w.Code, w.Body)
	}
}

func TestGetTranscriptTextRedactedAndPaged(t *testing.T) {
	r := newRig(t)
	r.connect(t, "u1", meet.ProviderTeams)
	w := r.call(t, "u1", "get_transcript", `{"meeting_id":"m-1"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var out struct {
		Text       string   `json:"text"`
		Format     string   `json:"format"`
		Speakers   []string `json:"speakers"`
		Duration   string   `json:"duration"`
		Redactions int      `json:"redactions"`
		Truncated  bool     `json:"truncated"`
		Meeting    meet.Meeting
	}
	decode(t, w, &out)
	if out.Format != "text" || out.Truncated || out.Duration != "00:00:04" || len(out.Speakers) != 2 {
		t.Errorf("answer: %+v", out)
	}
	if strings.Contains(out.Text, "483920") || out.Redactions != 1 || !strings.Contains(out.Text, "[one-time code removed]") {
		t.Errorf("the code is stripped: %q (%d)", out.Text, out.Redactions)
	}
	if !strings.HasPrefix(out.Text, "[00:00:00] Alice: ") || !strings.Contains(out.Text, "\n[00:00:02] Bob: Hi Alice\n") {
		t.Errorf("text: %q", out.Text)
	}
	if len(out.Meeting.Participants) != 2 || out.Meeting.Participants[0].Name != "Alice" {
		t.Errorf("speakers become participants: %+v", out.Meeting.Participants)
	}

	w = r.call(t, "u1", "get_transcript", `{"meeting_id":"m-1","format":"vtt"}`)
	decode(t, w, &out)
	if w.Code != http.StatusOK || !strings.HasPrefix(out.Text, "WEBVTT") || strings.Contains(out.Text, "483920") {
		t.Errorf("vtt: %d %q", w.Code, out.Text)
	}

	if w := r.call(t, "u1", "get_transcript", `{"meeting_id":"m-2"}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("no transcript: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "get_transcript", `{"meeting_id":"nope"}`); w.Code != http.StatusNotFound {
		t.Errorf("unknown: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "get_transcript", `{"meeting_id":"m-1","format":"pdf"}`); w.Code != http.StatusBadGateway {
		t.Errorf("bad format: %d %s", w.Code, w.Body)
	}
}

func TestPaging(t *testing.T) {
	text := strings.Repeat("[00:00:00] A: "+strings.Repeat("x", 100)+"\n", 1000)
	page, next := pageOf(text, 0)
	if next == 0 || len(page) > pageBytes || !strings.HasSuffix(page, "\n") {
		t.Fatalf("first page: %d bytes, next %d", len(page), next)
	}
	var total int
	for off := 0; ; {
		p, n := pageOf(text, off)
		total += len(p)
		if n == 0 {
			break
		}
		off = n
	}
	if total != len(text) {
		t.Errorf("the pages add up to %d, not %d", total, len(text))
	}
	if p, n := pageOf(text, len(text)+5); p != "" || n != 0 {
		t.Errorf("past the end: %q %d", p, n)
	}
}

func TestSaveTranscriptNeedsTheFolder(t *testing.T) {
	r := newRig(t)
	r.connect(t, "u1", meet.ProviderZoom)
	w := r.call(t, "u1", "save_transcript", `{"meeting_id":"m-1"}`)
	if w.Code != http.StatusPreconditionFailed || !strings.Contains(w.Body.String(), "has not approved the Meeting transcripts folder") {
		t.Fatalf("without the folder: %d %s", w.Code, w.Body)
	}
	r.archive.approved = true
	w = r.call(t, "u1", "save_transcript", `{"meeting_id":"m-1"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	var out struct {
		Saved archive.Saved `json:"saved"`
	}
	decode(t, w, &out)
	if out.Saved.MarkdownPath != "AppData/Meeting transcripts/2026-09-14 Weekly sync.md" || out.Saved.Indexed {
		t.Errorf("saved: %+v", out.Saved)
	}
	if len(r.archive.saves) != 1 || r.archive.saves[0].ID != "m-1" {
		t.Errorf("saves: %+v", r.archive.saves)
	}
	if w := r.call(t, "u1", "save_transcript", `{"meeting_id":"m-2"}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("no transcript to save: %d %s", w.Code, w.Body)
	}

	// Off a deployment with no Drive.
	r.s.SetArchive(nil)
	if w := r.call(t, "u1", "save_transcript", `{"meeting_id":"m-1"}`); w.Code != http.StatusServiceUnavailable {
		t.Errorf("no archive: %d %s", w.Code, w.Body)
	}
}

func TestChangesCursorMovesOnTranscriptTime(t *testing.T) {
	r := newRig(t)
	r.connect(t, "u1", meet.ProviderZoom)
	// A first call establishes the cursor at now: what exists is history.
	w := r.call(t, "u1", "changes", `{}`)
	var out struct {
		Changes []map[string]any `json:"changes"`
		Cursor  string           `json:"cursor"`
	}
	decode(t, w, &out)
	if w.Code != http.StatusOK || len(out.Changes) != 0 || out.Cursor != now.Format(time.RFC3339Nano) {
		t.Fatalf("first call: %d %+v", w.Code, out)
	}
	// A cursor from two days ago sees yesterday's transcript, and moves.
	since := now.Add(-48 * time.Hour).Format(time.RFC3339Nano)
	w = r.call(t, "u1", "changes", `{"since":"`+since+`","wait_seconds":0}`)
	decode(t, w, &out)
	if len(out.Changes) != 1 || out.Changes[0]["id"] != "m-1" || out.Changes[0]["kind"] != "transcript_available" {
		t.Fatalf("changes: %+v", out)
	}
	if out.Cursor != now.Add(-23*time.Hour).Format(time.RFC3339Nano) {
		t.Errorf("cursor: %s", out.Cursor)
	}
	// From that cursor there is nothing new.
	w = r.call(t, "u1", "changes", `{"since":"`+out.Cursor+`"}`)
	decode(t, w, &out)
	if len(out.Changes) != 0 {
		t.Errorf("nothing new: %+v", out)
	}
	if w := r.call(t, "u1", "changes", `{"since":"yesterday"}`); w.Code != http.StatusBadGateway {
		t.Errorf("bad cursor: %d", w.Code)
	}
}

func TestAccountAndNoCredential(t *testing.T) {
	r := newRig(t)
	r.connect(t, "u1", meet.ProviderTeams)
	w := r.call(t, "u1", "account", `{}`)
	var out struct {
		Account map[string]any `json:"account"`
		Archive archive.Status `json:"archive"`
	}
	decode(t, w, &out)
	if w.Code != http.StatusOK || out.Account["provider"] != "teams" || out.Account["user"] != "me@example.org" || out.Archive.Approved {
		t.Errorf("account: %d %+v", w.Code, out)
	}
	if strings.Contains(w.Body.String(), "rt-1") || strings.Contains(w.Body.String(), "at-1") {
		t.Errorf("the credential leaked: %s", w.Body)
	}
	w = r.call(t, "nobody", "account", `{}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"credential_needed":true`) || !strings.Contains(w.Body.String(), meet.Kind) {
		t.Errorf("no credential: %d %s", w.Code, w.Body)
	}
}

func TestTokenRefusedIsSaidPlainly(t *testing.T) {
	r := newRig(t)
	_ = r.s.credStore().Put(context.Background(), "u1", store.Account{Provider: meet.ProviderZoom, User: "me@example.org", RefreshToken: "rt", AccessToken: "bad", Expiry: time.Now().Add(time.Hour)})
	r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), mintBody(nil))
	w := r.call(t, "u1", "list_meetings", `{}`)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "ask_again") {
		t.Errorf("refused sign-in: %d %s", w.Code, w.Body)
	}
}

// ---------------------------------------------------------------- setup

// The address comes first, and decides the next step: a Microsoft address
// may hold its meetings on Teams or on Zoom and gets that one choice, among
// the providers this deployment has a client for; any other address goes
// straight to Zoom. No client at all is a sentence with nothing to fill.
func TestSetupAsksTheAddressThenBranchesOnWhoHostsIt(t *testing.T) {
	r := newRig(t)
	w := r.do(http.MethodGet, "/v1/capabilities/setup", asHolder("u1"), "")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var out struct {
		Needed          bool                `json:"needed"`
		Prerequisites   []map[string]string `json:"prerequisites"`
		RequestedSchema struct {
			Properties map[string]map[string]any `json:"properties"`
			Required   []string                  `json:"required"`
		} `json:"requestedSchema"`
	}
	decode(t, w, &out)
	if !out.Needed || len(out.RequestedSchema.Properties) != 1 || out.RequestedSchema.Properties["user"] == nil {
		t.Errorf("first step is the address alone: %s", w.Body)
	}
	// The folder is listed for the wallet to complete first.
	if len(out.Prerequisites) != 1 || out.Prerequisites[0]["nonce"] != "nonce-1" || out.Prerequisites[0]["app_host"] != "meetings.apps.example" {
		t.Errorf("prerequisites: %v", out.Prerequisites)
	}
	r.archive.approved = true
	w = r.do(http.MethodGet, "/v1/capabilities/setup", asHolder("u1"), "")
	decode(t, w, &out)
	if len(out.Prerequisites) != 0 {
		t.Errorf("approved: nothing to complete first: %v", out.Prerequisites)
	}

	type elicit struct {
		Elicit struct {
			Message         string `json:"message"`
			RequestedSchema struct {
				Properties map[string]map[string]any `json:"properties"`
			} `json:"requestedSchema"`
		} `json:"elicit"`
	}
	ask := func(setup map[string]any) (int, elicit, string) {
		w := r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), mintBody(setup))
		var got elicit
		if w.Code == http.StatusPreconditionRequired {
			decode(t, w, &got)
		}
		return w.Code, got, w.Body.String()
	}
	enumOf := func(got elicit, k string) []any {
		v, _ := got.Elicit.RequestedSchema.Properties[k]["enum"].([]any)
		return v
	}

	// No client configured yet: said plainly, nothing to fill, whoever
	// hosts the address.
	for _, user := range []string{"me@example.org", "me@tenant.example", "me@outlook.com"} {
		code, got, body := ask(map[string]any{"user": user})
		if code != http.StatusPreconditionRequired || len(got.Elicit.RequestedSchema.Properties) != 0 || !strings.Contains(got.Elicit.Message, "no sign-in configured") {
			t.Fatalf("%s with no client: %d %s", user, code, body)
		}
	}

	// Zoom alone configured: every address goes straight to Zoom's button,
	// with no choice drawn, because Teams cannot connect anyone here.
	r.s.flows.Flow(meet.ProviderZoom).SetClient("cid", "csecret")
	for _, user := range []string{"me@example.org", "me@tenant.example"} {
		code, got, body := ask(map[string]any{"user": user})
		if code != http.StatusPreconditionRequired {
			t.Fatalf("%s: %d %s", user, code, body)
		}
		x, _ := got.Elicit.RequestedSchema.Properties["grant"]["x-privasys-oauth"].(map[string]any)
		if x == nil || x["provider"] != "Zoom" || x["start_url"] != "https://meetings.apps.example/v1/oauth/start?kind=meeting.transcripts&provider=zoom" {
			t.Errorf("%s: button: %v", user, got.Elicit.RequestedSchema.Properties["grant"])
		}
		if opts := enumOf(got, "provider"); len(opts) != 1 || opts[0] != "Zoom" {
			t.Errorf("%s: no choice to make: %v", user, opts)
		}
		if got.Elicit.RequestedSchema.Properties["user"]["default"] != user {
			t.Errorf("%s: the address is carried forward: %v", user, got.Elicit.RequestedSchema.Properties["user"])
		}
	}

	// Both configured: a Microsoft address gets the choice, then the button
	// for what it chose; any other address still goes straight to Zoom.
	r.s.flows.Flow(meet.ProviderTeams).SetClient("cid", "csecret")
	code, got, body := ask(map[string]any{"user": "me@tenant.example"})
	if code != http.StatusPreconditionRequired || got.Elicit.RequestedSchema.Properties["grant"] != nil {
		t.Fatalf("a Microsoft address is asked where its meetings are: %d %s", code, body)
	}
	if opts := enumOf(got, "provider"); len(opts) != 2 || opts[0] != "Microsoft Teams" || opts[1] != "Zoom" {
		t.Errorf("choices: %v", opts)
	}
	code, got, body = ask(map[string]any{"user": "me@tenant.example", "provider": "Microsoft Teams"})
	x, _ := got.Elicit.RequestedSchema.Properties["grant"]["x-privasys-oauth"].(map[string]any)
	if code != http.StatusPreconditionRequired || x == nil || x["provider"] != "Microsoft" || x["start_url"] != "https://meetings.apps.example/v1/oauth/start?kind=meeting.transcripts&provider=teams" {
		t.Errorf("teams button: %d %s", code, body)
	}
	code, got, _ = ask(map[string]any{"user": "me@tenant.example", "provider": "Zoom"})
	if x, _ := got.Elicit.RequestedSchema.Properties["grant"]["x-privasys-oauth"].(map[string]any); code != http.StatusPreconditionRequired || x == nil || x["provider"] != "Zoom" {
		t.Errorf("a Microsoft 365 user may hold Zoom meetings: %v", got.Elicit.RequestedSchema.Properties["grant"])
	}
	code, got, body = ask(map[string]any{"user": "me@gmail.com", "provider": "Microsoft Teams"})
	if x, _ := got.Elicit.RequestedSchema.Properties["grant"]["x-privasys-oauth"].(map[string]any); code != http.StatusPreconditionRequired || x == nil || x["provider"] != "Zoom" {
		t.Errorf("Teams is never offered to an address that is not Microsoft's: %d %s", code, body)
	}
	if code, _, body := ask(map[string]any{"user": "not-an-address"}); code != http.StatusPreconditionRequired || !strings.Contains(body, `"user":{`) || strings.Contains(body, "x-privasys-oauth") {
		t.Errorf("no domain: %d %s", code, body)
	}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), mintBody(map[string]any{"user": "me@example.org", "grant": "unknown"}))
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), "unknown, already used or expired") {
		t.Errorf("unknown grant: %d %s", w.Code, w.Body)
	}
}

// A mint for an account already in memory, for the same address, does not
// touch the provider and hands the wallet the current refresh token.
func TestMintForAConnectedAccountKeepsTheCurrentToken(t *testing.T) {
	r := newRig(t)
	r.s.flows.Flow(meet.ProviderTeams).SetClient("cid", "csecret")
	_ = r.s.credStore().Put(context.Background(), "u1", store.Account{Provider: meet.ProviderTeams, User: "me@tenant.example", RefreshToken: "rt-current", AccessToken: "at", Expiry: time.Now().Add(time.Hour)})
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), mintBody(map[string]any{"user": "me@tenant.example", "provider": "Microsoft Teams", "kept": map[string]any{"refresh_token": "rt-stale", "provider": "teams"}}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"refresh_token":"rt-current"`) {
		t.Errorf("mint: %d %s", w.Code, w.Body)
	}
}

func TestManifestRoutesAllExist(t *testing.T) {
	r := newRig(t)
	r.connect(t, "u1", meet.ProviderZoom)
	for _, tool := range []string{"list_meetings", "get_transcript", "save_transcript", "changes", "account"} {
		w := r.do(http.MethodPost, "/api/v1/mcp/tools/"+tool, asUser("u1"), `{}`)
		if w.Code == http.StatusNotFound {
			t.Errorf("%s is not routed at the agent's path", tool)
		}
	}
	w := r.do(http.MethodGet, "/api/v1/mcp/tools", nil, "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"configure"`) || !strings.Contains(w.Body.String(), `"save_transcript"`) {
		t.Errorf("catalogue: %d %s", w.Code, w.Body)
	}
}
