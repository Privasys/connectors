// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package zoomdrv

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/meetings/internal/meet"
)

const sampleVTT = "WEBVTT\n\n1\n00:00:00.500 --> 00:00:02.000\nAlice: Hello\n\n2\n00:00:02.100 --> 00:00:04.000\nBob: Hi Alice\n"

// fakeZoom is the three calls the driver makes, plus the download host.
type fakeZoom struct {
	srv      *httptest.Server
	token    string
	requests []string
	// two recordings: one with a transcript, one without; and a UUID that
	// needs double encoding.
	pages int
}

func newFakeZoom(t *testing.T) *fakeZoom {
	t.Helper()
	f := &fakeZoom{token: "at-1"}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			http.Error(w, `{"code":124,"message":"Invalid access token."}`, http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /v2/users/me", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "u", "email": "Me@Example.org", "display_name": "Me Myself"})
	})
	recordings := func(base string) []map[string]any {
		return []map[string]any{
			{
				"uuid": "abc+def==", "id": 111, "topic": "Weekly sync", "host_email": "host@example.org",
				"start_time": "2026-09-10T09:00:00Z", "duration": 30,
				"recording_files": []map[string]any{
					{"id": "f1", "file_type": "MP4", "status": "completed", "recording_start": "2026-09-10T09:00:05Z", "recording_end": "2026-09-10T09:29:00Z", "download_url": base + "/download/f1"},
					{"id": "f2", "file_type": "TRANSCRIPT", "file_extension": "VTT", "status": "completed", "recording_start": "2026-09-10T09:00:05Z", "recording_end": "2026-09-10T09:29:30Z", "download_url": base + "/download/f2"},
				},
			},
			{
				"uuid": "/slash//uuid", "id": 222, "topic": "No transcript yet", "host_email": "host@example.org",
				"start_time": "2026-09-12T14:00:00Z", "duration": 15,
				"recording_files": []map[string]any{
					{"id": "f3", "file_type": "MP4", "status": "completed", "download_url": base + "/download/f3"},
					{"id": "f4", "file_type": "TRANSCRIPT", "status": "processing", "download_url": base + "/download/f4"},
				},
			},
		}
	}
	mux.HandleFunc("GET /v2/users/me/recordings", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		f.pages++
		q := r.URL.Query()
		if q.Get("page_size") != "300" || q.Get("from") == "" || q.Get("to") == "" {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		// Two pages: the first names a token, the second is empty.
		if q.Get("next_page_token") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"next_page_token": "p2", "meetings": recordings(f.srv.URL)})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"next_page_token": "", "meetings": []any{}})
	})
	mux.HandleFunc("GET /v2/meetings/{id}/recordings", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		// The mux decoded the path once; Zoom decodes a doubly encoded
		// UUID once more, so the fake does the same.
		id, _ := url.PathUnescape(r.PathValue("id"))
		for _, rec := range recordings(f.srv.URL) {
			if rec["uuid"] == id {
				_ = json.NewEncoder(w).Encode(rec)
				return
			}
		}
		http.Error(w, `{"code":3301,"message":"This recording does not exist."}`, http.StatusNotFound)
	})
	mux.HandleFunc("GET /download/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		if r.PathValue("id") != "f2" {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/vtt")
		_, _ = w.Write([]byte(sampleVTT))
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func open(t *testing.T, f *fakeZoom) *Driver {
	t.Helper()
	d, profile, err := Open(context.Background(), Config{
		APIBase: f.srv.URL + "/v2", HTTPClient: f.srv.Client(),
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
	f := newFakeZoom(t)
	open(t, f)
	_, _, err := Open(context.Background(), Config{APIBase: f.srv.URL + "/v2", HTTPClient: f.srv.Client(),
		Token: func(context.Context) (string, error) { return "wrong", nil }})
	if !errors.Is(err, meet.ErrLogin) {
		t.Errorf("a refused bearer: %v", err)
	}
}

func TestMeetingsListsRecordingsWithWhetherATranscriptExists(t *testing.T) {
	f := newFakeZoom(t)
	d := open(t, f)
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	ms, err := d.Meetings(context.Background(), from, from.Add(40*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 {
		t.Fatalf("meetings: %+v", ms)
	}
	// Newest first.
	if ms[0].ID != "/slash//uuid" || ms[0].HasTranscript || !ms[0].HasRecording {
		t.Errorf("a recording whose transcript is still processing: %+v", ms[0])
	}
	m := ms[1]
	if m.ID != "abc+def==" || m.Title != "Weekly sync" || !m.HasTranscript || m.Provider != meet.ProviderZoom {
		t.Errorf("meeting: %+v", m)
	}
	if m.Organiser == nil || m.Organiser.Address != "host@example.org" {
		t.Errorf("organiser: %+v", m.Organiser)
	}
	if m.End.Sub(m.Start) != 30*time.Minute {
		t.Errorf("end from duration: %v %v", m.Start, m.End)
	}
	if !m.TranscriptAt.Equal(time.Date(2026, 9, 10, 9, 29, 30, 0, time.UTC)) {
		t.Errorf("transcript_at is the transcript file's end: %v", m.TranscriptAt)
	}
	// A 40-day window is asked for in two chunks of at most 30 days, each
	// followed to its second page.
	if f.pages != 4 {
		t.Errorf("pages fetched: %d (%v)", f.pages, f.requests)
	}
}

func TestTranscriptDownloadsTheVTT(t *testing.T) {
	f := newFakeZoom(t)
	d := open(t, f)
	tr, err := d.Transcript(context.Background(), "abc+def==")
	if err != nil {
		t.Fatal(err)
	}
	if string(tr.VTT) != sampleVTT || tr.Meeting.Title != "Weekly sync" || !tr.Meeting.HasTranscript {
		t.Errorf("transcript: %+v %q", tr.Meeting, tr.VTT)
	}
	// The uuid with a plus is escaped once; the one with slashes twice.
	if !strings.Contains(strings.Join(f.requests, "\n"), "/v2/meetings/abc+def==/recordings") {
		t.Errorf("uuid escaping: %v", f.requests)
	}
	if _, err := d.Transcript(context.Background(), "/slash//uuid"); !errors.Is(err, meet.ErrNoTranscript) {
		t.Errorf("no transcript yet: %v", err)
	}
	if !strings.Contains(strings.Join(f.requests, "\n"), "/v2/meetings/%252Fslash%252F%252Fuuid/recordings") {
		t.Errorf("double escaping: %v", f.requests)
	}
	if _, err := d.Transcript(context.Background(), "nope"); !errors.Is(err, meet.ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
}

func TestBearerNeverGoesToAForeignDownloadHost(t *testing.T) {
	f := newFakeZoom(t)
	d := open(t, f)
	for _, u := range []string{"https://evil.example/x", "http://zoom.us/x", "https://notzoom.usx/x"} {
		if d.allowedDownload(u) {
			t.Errorf("%s allowed", u)
		}
	}
	for _, u := range []string{"https://us02web.zoom.us/rec/download/x", "https://zoom.us/x", f.srv.URL + "/download/f2"} {
		if !d.allowedDownload(u) {
			t.Errorf("%s refused", u)
		}
	}
}
