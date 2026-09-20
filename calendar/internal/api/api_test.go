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

	"github.com/Privasys/connectors/calendar/internal/cal"
	"github.com/Privasys/connectors/calendar/internal/caldavdrv"
	"github.com/Privasys/connectors/calendar/internal/config"
	"github.com/Privasys/connectors/calendar/internal/discover"
	"github.com/Privasys/connectors/calendar/internal/store"
	"github.com/Privasys/connectors/sdk/caller"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
	"github.com/Privasys/connectors/sdk/provider"
)

// fakeMX is the DNS the tests see: one custom domain at Google Workspace,
// one at Microsoft 365, and every other domain hosted elsewhere or unknown.
func fakeMX(_ context.Context, domain string) ([]*net.MX, error) {
	switch domain {
	case "workspace.example":
		return []*net.MX{{Host: "aspmx.l.google.com."}}, nil
	case "tenant.example":
		return []*net.MX{{Host: "tenant-example.mail.protection.outlook.com."}}, nil
	case "self.example":
		return []*net.MX{{Host: "mail.self.example."}}, nil
	}
	return nil, errors.New("no such domain")
}

const testApp = "590ebdc31b63401fbbb822d5f3886c5e"

var day = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

// fakeDriver is a calendar with three events: one of the holder's, one
// proposed by the assistant, and one free (a birthday).
type fakeDriver struct {
	cfg      caldavdrv.Config
	events   []cal.Event
	proposed []cal.Proposal
	deleted  []string
	closed   bool
}

func newFakeDriver(cfg caldavdrv.Config) *fakeDriver {
	return &fakeDriver{cfg: cfg, events: []cal.Event{
		{ID: "theirs", Calendar: "c1", Title: "Board meeting", Start: day.Add(9 * time.Hour), End: day.Add(11 * time.Hour),
			Attendees: []cal.Attendee{{Name: "Alice", Address: "alice@example.org", Status: "accepted"}}, Description: "Q3 numbers"},
		{ID: "mine", Calendar: "c1", Title: "Coffee", Start: day.Add(10 * time.Hour), End: day.Add(12 * time.Hour), Proposed: true, Status: "tentative"},
		{ID: "bday", Calendar: "c1", Title: "Bob's birthday", Start: day, End: day.Add(24 * time.Hour), AllDay: true, Free: true},
		{ID: "late", Calendar: "c1", Title: "Dinner", Start: day.Add(19 * time.Hour), End: day.Add(21 * time.Hour)},
	}}
}

func (f *fakeDriver) Calendars(context.Context) ([]cal.Calendar, error) {
	return []cal.Calendar{{ID: "c1", Name: "Personal", Primary: true}}, nil
}
func (f *fakeDriver) Events(_ context.Context, _ string, from, to time.Time) ([]cal.Event, error) {
	var out []cal.Event
	for _, ev := range f.events {
		if ev.Start.Before(to) && ev.End.After(from) {
			out = append(out, ev)
		}
	}
	return out, nil
}
func (f *fakeDriver) Get(_ context.Context, id string) (cal.Event, error) {
	for _, ev := range f.events {
		if ev.ID == id {
			return ev, nil
		}
	}
	if id == "stale" {
		return cal.Event{}, cal.ErrStale
	}
	return cal.Event{}, cal.ErrNotFound
}
func (f *fakeDriver) Propose(_ context.Context, _ string, p cal.Proposal) (cal.Event, error) {
	f.proposed = append(f.proposed, p)
	return cal.Event{ID: "new", Title: p.Title, Start: p.Start, End: p.End, AllDay: p.AllDay, Proposed: true, Status: "tentative"}, nil
}
func (f *fakeDriver) Update(_ context.Context, id string, p cal.Patch) (cal.Event, error) {
	ev, err := f.Get(context.Background(), id)
	if err != nil {
		return cal.Event{}, err
	}
	if !ev.Proposed {
		return cal.Event{}, cal.ErrNotProposed
	}
	if p.Title != nil {
		ev.Title = *p.Title
	}
	return ev, nil
}
func (f *fakeDriver) Delete(_ context.Context, id string) error {
	ev, err := f.Get(context.Background(), id)
	if err != nil {
		return err
	}
	if !ev.Proposed {
		return cal.ErrNotProposed
	}
	f.deleted = append(f.deleted, id)
	return nil
}
func (f *fakeDriver) Changes(context.Context, string, time.Duration) ([]cal.Change, string, error) {
	return nil, "cur-1", nil
}
func (f *fakeDriver) Close() error { f.closed = true; return nil }

// rig is a connector whose accounts open onto fake drivers: an app password
// of "pw" is accepted at any endpoint, "wrong" is the server's refusal,
// anything else is a server that cannot be reached; a bearer is asked for
// and recorded.
type rig struct {
	s       *Server
	drivers []*fakeDriver
	bearers []string
}

func newRig(t *testing.T, requireGrant bool) *rig {
	t.Helper()
	r := &rig{s: New(store.NewMemory(), grant.NewMemory(), requireGrant)}
	r.s.resolver = &discover.Resolver{} // offline: guesses only
	r.s.who = &provider.Resolver{LookupMX: fakeMX}
	r.s.open = func(ctx context.Context, cfg caldavdrv.Config) (cal.Driver, error) {
		if cfg.Token != nil {
			tok, err := cfg.Token(ctx)
			if err != nil {
				return nil, err
			}
			r.bearers = append(r.bearers, tok)
			if tok == "bad-token" {
				return nil, caldavdrv.ErrLogin
			}
		} else {
			switch cfg.Password {
			case "pw":
			case "wrong":
				return nil, caldavdrv.ErrLogin
			default:
				return nil, errors.New("dial tcp: connection refused")
			}
		}
		d := newFakeDriver(cfg)
		r.drivers = append(r.drivers, d)
		return d, nil
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
	req.Host = "cal.apps.example"
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
		"nonce": "n-1", "subject_app_id": testApp, "kind": cal.Kind,
		"permissions": []string{"read", "write"}, "expires_unix": time.Now().Add(24 * time.Hour).Unix(),
	}
	if setup != nil {
		req["setup"] = setup
	}
	b, _ := json.Marshal(req)
	return string(b)
}

// connect puts a proven password account in memory and mints, the way the
// wallet does on one tap.
func (r *rig) connect(t *testing.T, sub string) {
	t.Helper()
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder(sub), mintBody(map[string]any{"user": sub + "@example.org", "password": "pw"}))
	if w.Code != http.StatusOK {
		t.Fatalf("connect: %d %s", w.Code, w.Body)
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

func TestListEventsDefaultsAndBounds(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	w := r.call(t, "u1", "list_events", `{"from":"2026-10-05","to":"2026-10-06"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var got struct {
		Events []cal.Event `json:"events"`
	}
	decode(t, w, &got)
	if len(got.Events) != 4 {
		t.Fatalf("want the day's events, got %d", len(got.Events))
	}
	if w := r.call(t, "u1", "list_events", `{"from":"2026-10-05","to":"2027-01-01"}`); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "62 days") {
		t.Fatalf("a window over the bound is refused with the bound: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "list_events", `{"from":"tomorrow"}`); w.Code == http.StatusOK {
		t.Fatal("a time that is not RFC 3339 or a date is refused")
	}
	// No window at all is the coming week: the fake has nothing there, and
	// the answer is an empty list rather than null.
	w = r.call(t, "u1", "list_events", `{}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"events":[]`) {
		t.Fatalf("default window: %d %s", w.Code, w.Body)
	}
	if _, _, err := window("", "", 7*24*time.Hour, day); err != nil {
		t.Fatal(err)
	}
	from, to, _ := window("2026-10-05", "", 7*24*time.Hour, day)
	if !from.Equal(day) || !to.Equal(day.AddDate(0, 0, 7)) {
		t.Fatalf("window defaults: %s %s", from, to)
	}
}

func TestSearchFiltersTheWindow(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	w := r.call(t, "u1", "search", `{"query":"ALICE numbers","from":"2026-10-05","to":"2026-10-06"}`)
	var got struct {
		Events []cal.Event `json:"events"`
	}
	decode(t, w, &got)
	if w.Code != http.StatusOK || len(got.Events) != 1 || got.Events[0].Title != "Board meeting" {
		t.Fatalf("search: %d %+v", w.Code, got.Events)
	}
	if w := r.call(t, "u1", "search", `{"query":"   "}`); w.Code == http.StatusOK {
		t.Fatal("an empty query is refused")
	}
	w = r.call(t, "u1", "search", `{"query":"nothing-like-this","from":"2026-10-05","to":"2026-10-06"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"events":[]`) {
		t.Fatalf("no hits is an empty list: %s", w.Body)
	}
}

// Busy time merges overlaps, ignores the free birthday and the assistant's
// own tentative proposal, and is clipped to the window.
func TestFreeBusyMergesAndIgnoresProposalsAndFreeTime(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	w := r.call(t, "u1", "free_busy", `{"from":"2026-10-05T10:00:00Z","to":"2026-10-05T20:00:00Z"}`)
	var got struct {
		Busy []cal.Busy `json:"busy"`
	}
	decode(t, w, &got)
	if w.Code != http.StatusOK || len(got.Busy) != 2 {
		t.Fatalf("busy: %d %+v", w.Code, got.Busy)
	}
	if !got.Busy[0].Start.Equal(day.Add(10*time.Hour)) || !got.Busy[0].End.Equal(day.Add(11*time.Hour)) {
		t.Errorf("the meeting is clipped to the window: %+v", got.Busy[0])
	}
	if !got.Busy[1].Start.Equal(day.Add(19*time.Hour)) || !got.Busy[1].End.Equal(day.Add(20*time.Hour)) {
		t.Errorf("dinner is clipped at the end: %+v", got.Busy[1])
	}
	merged := busyIntervals([]cal.Event{
		{Start: day, End: day.Add(2 * time.Hour)},
		{Start: day.Add(time.Hour), End: day.Add(3 * time.Hour)},
		{Start: day.Add(5 * time.Hour), End: day.Add(6 * time.Hour), Status: "cancelled"},
	}, day, day.Add(24*time.Hour))
	if len(merged) != 1 || !merged[0].End.Equal(day.Add(3*time.Hour)) {
		t.Fatalf("merge: %+v", merged)
	}
}

func TestProposeUpdateDeleteAndTheirStatuses(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	w := r.call(t, "u1", "propose_event", `{"title":"Lunch","start":"2026-10-05T12:00:00Z","end":"2026-10-05T13:00:00Z","attendees":["alice@example.org"],"run_id":"run-1"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "nobody has been invited") {
		t.Fatalf("propose: %d %s", w.Code, w.Body)
	}
	// The last driver opened: the probe at connect time was the first.
	drv := r.drivers[len(r.drivers)-1]
	if len(drv.proposed) != 1 || drv.proposed[0].Ref != "run-1" || drv.proposed[0].AllDay || len(drv.proposed[0].Attendees) != 1 {
		t.Fatalf("the proposal that reached the driver: %+v", drv.proposed)
	}
	w = r.call(t, "u1", "propose_event", `{"title":"Away","start":"2026-10-06","end":"2026-10-08"}`)
	if w.Code != http.StatusOK || !drv.proposed[1].AllDay {
		t.Fatalf("dates make an all-day proposal: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "propose_event", `{"title":"x","start":"2026-10-06","end":"2026-10-06T10:00:00Z"}`); w.Code == http.StatusOK {
		t.Fatal("a date and a time do not mix")
	}
	if w := r.call(t, "u1", "propose_event", `{"title":"x","start":"2026-10-06T10:00:00Z"}`); w.Code == http.StatusOK {
		t.Fatal("end is required")
	}

	for _, c := range []struct {
		tool, body string
		want       int
	}{
		{"update_event", `{"id":"theirs","title":"Renamed"}`, http.StatusUnprocessableEntity},
		{"delete_event", `{"id":"theirs"}`, http.StatusUnprocessableEntity},
		{"update_event", `{"id":"stale","title":"x"}`, http.StatusConflict},
		{"get_event", `{"id":"stale"}`, http.StatusConflict},
		{"get_event", `{"id":"gone"}`, http.StatusNotFound},
		{"update_event", `{"id":"mine"}`, http.StatusBadGateway},
		{"update_event", `{"id":"mine","title":"Renamed"}`, http.StatusOK},
		{"delete_event", `{"id":"mine"}`, http.StatusOK},
	} {
		if w := r.call(t, "u1", c.tool, c.body); w.Code != c.want {
			t.Errorf("%s %s: want %d, got %d %s", c.tool, c.body, c.want, w.Code, w.Body)
		}
	}
	if len(drv.deleted) != 1 || drv.deleted[0] != "mine" {
		t.Fatalf("deleted: %v", drv.deleted)
	}
	if w := r.call(t, "u1", "update_event", `{"id":"theirs","title":"Renamed"}`); !strings.Contains(w.Body.String(), "not proposed by the assistant") {
		t.Fatalf("the refusal is a sentence: %s", w.Body)
	}
}

func TestReadOnlyCapabilityCannotPropose(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	body, _ := json.Marshal(map[string]any{
		"nonce": "n-2", "subject_app_id": testApp, "kind": cal.Kind,
		"permissions": []string{"read"}, "expires_unix": time.Now().Add(24 * time.Hour).Unix(),
	})
	if w := r.do(http.MethodPost, "/v1/capabilities", asHolder("u1"), string(body)); w.Code != http.StatusOK {
		t.Fatalf("re-mint read-only: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "list_events", `{}`); w.Code != http.StatusOK {
		t.Fatalf("read should be allowed: %d", w.Code)
	}
	for _, tool := range []string{"propose_event", "update_event", "delete_event"} {
		if w := r.call(t, "u1", tool, `{"id":"mine","title":"x","start":"2026-10-06","end":"2026-10-07"}`); w.Code != http.StatusForbidden {
			t.Errorf("%s under read-only: %d", tool, w.Code)
		}
	}
}

func TestChangesAndAccount(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	w := r.call(t, "u1", "changes", `{"since":"","wait_seconds":600}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"changes":[]`) || !strings.Contains(w.Body.String(), `"cursor":"cur-1"`) {
		t.Fatalf("changes: %d %s", w.Code, w.Body)
	}
	w = r.call(t, "u1", "account", `{}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "u1@example.org") || !strings.Contains(w.Body.String(), "Personal") {
		t.Fatalf("account: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), `"pw"`) || strings.Contains(w.Body.String(), "refresh") {
		t.Fatalf("the account tool returned a credential: %s", w.Body)
	}
	// Every advertised tool is routed.
	for _, name := range []string{"list_calendars", "list_events", "get_event", "search", "free_busy", "propose_event", "update_event", "delete_event", "changes", "account"} {
		if w := r.call(t, "u1", name, `{}`); w.Code == http.StatusNotFound && strings.Contains(w.Body.String(), "404 page not found") {
			t.Errorf("tool %q is in the manifest but has no route", name)
		}
	}
}

// A holder whose credential is not in memory gets the refusal that sends
// the agent to their device, naming this connector's kind.
func TestNoCredentialNamesTheKind(t *testing.T) {
	r := newRig(t, true)
	w := r.call(t, "nobody", "list_events", `{}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"credential_needed":true`) || !strings.Contains(w.Body.String(), cal.Kind) || !strings.Contains(w.Body.String(), "calendar details") {
		t.Fatalf("refusal: %d %s", w.Code, w.Body)
	}
}

// ---------------------------------------------------------------- setup

// The first question is the address alone; the second depends on it.
func TestSetupAsksTheAddressFirst(t *testing.T) {
	r := newRig(t, true)
	w := r.do(http.MethodGet, "/v1/capabilities/setup", asHolder("new"), "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"needed":true`) || strings.Contains(w.Body.String(), `"password":`) || strings.Contains(w.Body.String(), `"grant":`) {
		t.Fatalf("first step: %d %s", w.Code, w.Body)
	}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("new"), mintBody(map[string]any{"user": "me@example.org"}))
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), `"secrets":["password"]`) || !strings.Contains(w.Body.String(), "me@example.org") {
		t.Fatalf("second step for an ordinary address is the app password: %d %s", w.Code, w.Body)
	}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("new"), mintBody(map[string]any{"user": "not-an-address"}))
	if w.Code != http.StatusPreconditionRequired || strings.Contains(w.Body.String(), `"password":`) {
		t.Fatalf("an address without a domain is asked again: %d %s", w.Code, w.Body)
	}
}

func TestPasswordSetupProvesAgainstTheServerFound(t *testing.T) {
	r := newRig(t, true)
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder("h"), mintBody(map[string]any{"user": "me@example.org", "password": "wrong"}))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "refused these details") {
		t.Fatalf("a refused password: %d %s", w.Code, w.Body)
	}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("h"), mintBody(map[string]any{"user": "me@example.org", "password": "unreachable"}))
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), `"CalDAV server"`) || !strings.Contains(w.Body.String(), "https://caldav.example.org/") {
		t.Fatalf("no server reached is one more question naming what was tried: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "unreachable") {
		t.Fatal("the password was echoed")
	}
	w = r.do(http.MethodPost, "/v1/capabilities", asHolder("h"), mintBody(map[string]any{"user": "me@example.org", "password": "pw", "host": "dav.example.org/cal/"}))
	if w.Code != http.StatusOK {
		t.Fatalf("a named server: %d %s", w.Code, w.Body)
	}
	var got struct {
		ServiceResult map[string]string `json:"service_result"`
		Keep          *json.RawMessage  `json:"keep"`
	}
	decode(t, w, &got)
	if got.ServiceResult["account"] != "me@example.org" || got.ServiceResult["kind"] != cal.Kind || got.Keep != nil {
		t.Fatalf("mint: %s", w.Body)
	}
	acct, err := r.s.credStore().Get(context.Background(), "h")
	if err != nil || acct.Provider != store.ProviderCalDAV || acct.Endpoint != "https://dav.example.org/cal/" || acct.Secret != "pw" {
		t.Fatalf("kept: %+v %v", acct, err)
	}
	if r.drivers[len(r.drivers)-1].cfg.Endpoint != "https://dav.example.org/cal/" {
		t.Fatal("the probe went elsewhere")
	}
}

// The address decides the second step. A Google or a Microsoft address,
// by its own domain or by its MX, gets the sign-in button for that
// provider with a start URL on this host, only when a client is
// configured; without one the answer is a sentence and nothing to fill. A
// custom domain hosted elsewhere gets the app password.
func TestSetupBranchesOnWhoHostsTheAddress(t *testing.T) {
	r := newRig(t, true)
	type elicit struct {
		Elicit struct {
			Message string `json:"message"`
			Schema  struct {
				Properties map[string]map[string]any `json:"properties"`
			} `json:"requestedSchema"`
		} `json:"elicit"`
	}
	ask := func(user string) (int, elicit, string) {
		w := r.do(http.MethodPost, "/v1/capabilities", asHolder("h"), mintBody(map[string]any{"user": user}))
		var got elicit
		if w.Code == http.StatusPreconditionRequired {
			decode(t, w, &got)
		}
		return w.Code, got, w.Body.String()
	}

	// No client configured: an honest sentence, no field, and never a
	// password for an account that has no app passwords.
	for _, user := range []string{"me@gmail.com", "me@workspace.example", "me@outlook.com", "me@tenant.example"} {
		code, got, body := ask(user)
		if code != http.StatusPreconditionRequired || len(got.Elicit.Schema.Properties) != 0 || !strings.Contains(got.Elicit.Message, "no ") || !strings.Contains(got.Elicit.Message, "sign-in configured") {
			t.Fatalf("%s with no client: %d %s", user, code, body)
		}
	}

	r.s.applyConfig(config.Config{GoogleClientID: "gcid", GoogleClientSecret: "gsecret", MicrosoftClientID: "mcid", MicrosoftClientSecret: "msecret"})
	for user, want := range map[string]string{
		"me@gmail.com":         "google",
		"me@workspace.example": "google",
		"me@outlook.com":       "microsoft",
		"me@tenant.example":    "microsoft",
	} {
		code, got, body := ask(user)
		if code != http.StatusPreconditionRequired {
			t.Fatalf("%s: %d %s", user, code, body)
		}
		x, _ := got.Elicit.Schema.Properties["grant"]["x-privasys-oauth"].(map[string]any)
		if x["provider"] != provider.Provider(want).Name() || x["start_url"] != "https://cal.apps.example/v1/oauth/start?kind=calendar.events&provider="+want {
			t.Fatalf("%s: the sign-in property: %+v", user, got.Elicit.Schema.Properties)
		}
		if _, ok := got.Elicit.Schema.Properties["password"]; ok {
			t.Fatalf("%s: a sign-in account is never asked for a password", user)
		}
		if _, ok := got.Elicit.Schema.Properties["provider"]; ok {
			t.Fatalf("%s: the holder is never asked to pick a provider the domain names", user)
		}
	}
	// Hosted elsewhere, or nowhere the resolver knows: the app password.
	for _, user := range []string{"me@self.example", "me@icloud.com", "me@nowhere.example"} {
		code, got, body := ask(user)
		if code != http.StatusPreconditionRequired || got.Elicit.Schema.Properties["password"] == nil || got.Elicit.Schema.Properties["grant"] != nil {
			t.Fatalf("%s: %d %s", user, code, body)
		}
	}
}
