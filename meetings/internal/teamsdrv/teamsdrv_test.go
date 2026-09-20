// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package teamsdrv

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/meetings/internal/meet"
)

const sampleVTT = "WEBVTT\n\n00:00:00.500 --> 00:00:02.000\n<v Alice Smith>Hello</v>\n\n00:00:02.100 --> 00:00:04.000\n<v Bob Jones>Hi Alice</v>\n"

var now = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

// fakeGraph is the five calls the driver makes: me, the calendar view in
// two pages, an online meeting by join link, its transcripts, and the
// transcript content.
type fakeGraph struct {
	srv      *httptest.Server
	requests []string
}

func newFakeGraph(t *testing.T) *fakeGraph {
	t.Helper()
	f := &fakeGraph{}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer at-1" {
			http.Error(w, `{"error":{"code":"InvalidAuthenticationToken"}}`, http.StatusUnauthorized)
			return false
		}
		if r.Header.Get("Prefer") != `outlook.timezone="UTC"` {
			http.Error(w, "no timezone preference", http.StatusBadRequest)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /v1.0/me", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"displayName": "Me Myself", "mail": "Me@Example.org", "userPrincipalName": "me@example.org"})
	})
	event := func(id, subject, start, end, join string) map[string]any {
		ev := map[string]any{
			"id": id, "subject": subject,
			"start":     map[string]string{"dateTime": start, "timeZone": "UTC"},
			"end":       map[string]string{"dateTime": end, "timeZone": "UTC"},
			"organizer": map[string]any{"emailAddress": map[string]string{"name": "Host Person", "address": "Host@Example.org"}},
			"attendees": []map[string]any{
				{"emailAddress": map[string]string{"name": "Alice Smith", "address": "alice@example.org"}},
				{"emailAddress": map[string]string{"name": "Bob Jones", "address": "bob@example.org"}},
			},
		}
		if join != "" {
			ev["isOnlineMeeting"] = true
			ev["onlineMeeting"] = map[string]string{"joinUrl": join}
		}
		return ev
	}
	mux.HandleFunc("GET /v1.0/me/calendarView", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		q := r.URL.Query()
		if q.Get("startDateTime") == "" || q.Get("endDateTime") == "" {
			http.Error(w, "no window", http.StatusBadRequest)
			return
		}
		if q.Get("page") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					event("ev-1", "Weekly sync", "2026-09-10T09:00:00.0000000", "2026-09-10T09:30:00.0000000", "https://teams.microsoft.com/l/meetup-join/one"),
					event("ev-2", "Lunch", "2026-09-11T12:00:00.0000000", "2026-09-11T13:00:00.0000000", ""),
					event("ev-3", "Still to come", "2026-09-16T09:00:00.0000000", "2026-09-16T09:30:00.0000000", "https://teams.microsoft.com/l/meetup-join/future"),
				},
				"@odata.nextLink": f.srv.URL + "/v1.0/me/calendarView?page=2&startDateTime=x&endDateTime=y",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				event("ev-4", "Design review", "2026-09-12T14:00:00.0000000", "2026-09-12T15:00:00.0000000", "https://teams.microsoft.com/l/meetup-join/two"),
				event("ev-5", "Someone else's", "2026-09-13T14:00:00.0000000", "2026-09-13T15:00:00.0000000", "https://teams.microsoft.com/l/meetup-join/foreign"),
			},
		})
	})
	meetings := map[string]map[string]any{
		"https://teams.microsoft.com/l/meetup-join/one": {"id": "om-1", "subject": "Weekly sync", "startDateTime": "2026-09-10T09:00:00Z", "endDateTime": "2026-09-10T09:30:00Z",
			"participants": map[string]any{
				"organizer": map[string]any{"upn": "host@example.org", "identity": map[string]any{"user": map[string]any{"displayName": "Host Person"}}},
				"attendees": []map[string]any{{"upn": "alice@example.org", "identity": map[string]any{"user": map[string]any{"displayName": "Alice Smith"}}}},
			}},
		"https://teams.microsoft.com/l/meetup-join/two": {"id": "om-2", "subject": "Design review", "startDateTime": "2026-09-12T14:00:00Z", "endDateTime": "2026-09-12T15:00:00Z"},
	}
	mux.HandleFunc("GET /v1.0/me/onlineMeetings", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		filter := r.URL.Query().Get("$filter")
		for link, om := range meetings {
			if filter == "JoinWebUrl eq '"+link+"'" {
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{om}})
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
	})
	mux.HandleFunc("GET /v1.0/me/onlineMeetings/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		for _, om := range meetings {
			if om["id"] == r.PathValue("id") {
				_ = json.NewEncoder(w).Encode(om)
				return
			}
		}
		http.Error(w, `{"error":{"code":"NotFound"}}`, http.StatusNotFound)
	})
	mux.HandleFunc("GET /v1.0/me/onlineMeetings/{id}/transcripts", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		if r.PathValue("id") != "om-1" {
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{
			{"id": "tr-old", "meetingId": "om-1", "createdDateTime": "2026-09-10T09:35:00Z"},
			{"id": "tr-new", "meetingId": "om-1", "createdDateTime": "2026-09-10T09:40:00Z"},
		}})
	})
	mux.HandleFunc("GET /v1.0/me/onlineMeetings/{id}/transcripts/{tid}/content", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		if r.URL.Query().Get("$format") != "text/vtt" || r.PathValue("tid") != "tr-new" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/vtt")
		_, _ = w.Write([]byte(sampleVTT))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func open(t *testing.T, f *fakeGraph) *Driver {
	t.Helper()
	d, profile, err := Open(context.Background(), Config{
		APIBase: f.srv.URL + "/v1.0", HTTPClient: f.srv.Client(), Now: func() time.Time { return now },
		Token: func(context.Context) (string, error) { return "at-1", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Address != "me@example.org" || profile.Name != "Me Myself" {
		t.Fatalf("profile: %+v", profile)
	}
	return d
}

func TestOpenProvesTheBearer(t *testing.T) {
	f := newFakeGraph(t)
	open(t, f)
	_, _, err := Open(context.Background(), Config{APIBase: f.srv.URL + "/v1.0", HTTPClient: f.srv.Client(),
		Token: func(context.Context) (string, error) { return "wrong", nil }})
	if !errors.Is(err, meet.ErrLogin) {
		t.Errorf("a refused bearer: %v", err)
	}
}

func TestMeetingsComeFromTheCalendar(t *testing.T) {
	f := newFakeGraph(t)
	d := open(t, f)
	ms, err := d.Meetings(context.Background(), now.Add(-10*24*time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Lunch has no join link and the future one has not happened: three
	// meetings, newest first, one of them unresolved.
	if len(ms) != 3 {
		t.Fatalf("meetings: %+v", ms)
	}
	if ms[0].ID != "event:ev-5" || ms[0].HasTranscript || ms[0].Title != "Someone else's" {
		t.Errorf("an unresolved meeting is listed from the calendar alone: %+v", ms[0])
	}
	if ms[1].ID != "om-2" || ms[1].HasTranscript {
		t.Errorf("a meeting with no transcript: %+v", ms[1])
	}
	m := ms[2]
	if m.ID != "om-1" || !m.HasTranscript || m.Provider != meet.ProviderTeams || m.Title != "Weekly sync" {
		t.Errorf("meeting: %+v", m)
	}
	if !m.TranscriptAt.Equal(time.Date(2026, 9, 10, 9, 40, 0, 0, time.UTC)) {
		t.Errorf("transcript_at is the newest transcript: %v", m.TranscriptAt)
	}
	if !m.Start.Equal(time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)) || !m.End.Equal(time.Date(2026, 9, 10, 9, 30, 0, 0, time.UTC)) {
		t.Errorf("times: %v %v", m.Start, m.End)
	}
	if m.Organiser == nil || m.Organiser.Address != "host@example.org" || m.Organiser.Name != "Host Person" {
		t.Errorf("organiser: %+v", m.Organiser)
	}
	if len(m.Participants) != 2 || m.Participants[1].Name != "Bob Jones" {
		t.Errorf("participants: %+v", m.Participants)
	}
	if strings.Contains(strings.Join(f.requests, "\n"), "future") {
		t.Errorf("a meeting still to come must not be looked up: %v", f.requests)
	}
}

func TestTranscriptReadsTheNewest(t *testing.T) {
	f := newFakeGraph(t)
	d := open(t, f)
	tr, err := d.Transcript(context.Background(), "om-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(tr.VTT) != sampleVTT || tr.Meeting.Title != "Weekly sync" || !tr.Meeting.HasTranscript {
		t.Errorf("transcript: %+v %q", tr.Meeting, tr.VTT)
	}
	if tr.Meeting.Organiser == nil || tr.Meeting.Organiser.Name != "Host Person" || len(tr.Meeting.Participants) != 1 {
		t.Errorf("people from the online meeting: %+v %+v", tr.Meeting.Organiser, tr.Meeting.Participants)
	}
	if _, err := d.Transcript(context.Background(), "om-2"); !errors.Is(err, meet.ErrNoTranscript) {
		t.Errorf("no transcript: %v", err)
	}
	if _, err := d.Transcript(context.Background(), "event:ev-5"); !errors.Is(err, meet.ErrNoTranscript) {
		t.Errorf("calendar-only id: %v", err)
	}
	if _, err := d.Transcript(context.Background(), "nope"); !errors.Is(err, meet.ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
}

func TestGraphTimes(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"2026-09-10T09:00:00.0000000", "2026-09-10T09:00:00Z"},
		{"2026-09-10T09:00:00Z", "2026-09-10T09:00:00Z"},
		{"2026-09-10T09:00:00.1234567Z", "2026-09-10T09:00:00Z"},
		{"", "0001-01-01T00:00:00Z"},
	} {
		if got := parseGraphTime(c.in).Format(time.RFC3339); got != c.want {
			t.Errorf("parseGraphTime(%q) = %s", c.in, got)
		}
	}
}
