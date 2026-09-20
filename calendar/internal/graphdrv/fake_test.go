// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package graphdrv

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGraph is enough of Microsoft Graph to exercise the driver: a
// signed-in user, two calendars, events with a change key that moves on
// every write, the calendar view with one page break, the extended
// property on read and write, and the delta query with a token that names
// how many changes the caller has seen.
type fakeGraph struct {
	srv *httptest.Server

	mu       sync.Mutex
	bearer   string
	events   map[string]map[string]any // Graph id -> the stored event
	order    []string
	changes  []string // Graph ids, in the order they changed; "-id" for a removal
	requests []string // "METHOD path", for assertions
	prefers  []string
	seq      int
	gone     bool // the next delta call answers 410
}

func newFakeGraph(t *testing.T) *fakeGraph {
	t.Helper()
	g := &fakeGraph{bearer: "at-1", events: map[string]map[string]any{}}
	g.add("cal-1", map[string]any{
		"subject": "Board meeting",
		"start":   map[string]string{"dateTime": "2026-10-05T09:00:00.0000000", "timeZone": "UTC"},
		"end":     map[string]string{"dateTime": "2026-10-05T11:00:00.0000000", "timeZone": "UTC"},
		"body":    map[string]string{"contentType": "text", "content": "Q3 numbers. Your verification code is 483920."},
		"attendees": []map[string]any{
			{"emailAddress": map[string]string{"name": "Alice", "address": "Alice@example.org"}, "status": map[string]string{"response": "accepted"}},
			{"emailAddress": map[string]string{"name": "Bob", "address": "bob@example.org"}, "status": map[string]string{"response": "tentativelyAccepted"}},
		},
		"organizer":     map[string]any{"emailAddress": map[string]string{"name": "Alice", "address": "alice@example.org"}},
		"isOrganizer":   false,
		"showAs":        "busy",
		"location":      map[string]string{"displayName": "Room 4"},
		"onlineMeeting": map[string]string{"joinUrl": "https://teams.example/join/1"},
	})
	g.add("cal-1", map[string]any{
		"subject":        "Standup",
		"start":          map[string]string{"dateTime": "2026-10-06T09:00:00.0000000", "timeZone": "UTC"},
		"end":            map[string]string{"dateTime": "2026-10-06T09:15:00.0000000", "timeZone": "UTC"},
		"isOrganizer":    true,
		"showAs":         "busy",
		"type":           "occurrence",
		"seriesMasterId": "master-1",
	})
	g.add("cal-2", map[string]any{
		"subject":  "Bob's birthday",
		"start":    map[string]string{"dateTime": "2026-10-05T00:00:00.0000000", "timeZone": "UTC"},
		"end":      map[string]string{"dateTime": "2026-10-06T00:00:00.0000000", "timeZone": "UTC"},
		"isAllDay": true,
		"showAs":   "free",
	})
	g.events["master-1"] = map[string]any{
		"id": "master-1", "changeKey": "m1", "subject": "Standup", "type": "seriesMaster", "calendar": "cal-1",
		"recurrence": map[string]any{
			"pattern": map[string]any{"type": "weekly", "interval": 1, "daysOfWeek": []string{"monday", "wednesday"}},
			"range":   map[string]any{"type": "endDate", "endDate": "2026-12-31"},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1.0/me", func(w http.ResponseWriter, r *http.Request) {
		if !g.auth(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"mail": "Me@Example.org", "userPrincipalName": "me@example.org", "displayName": "Me"})
	})
	mux.HandleFunc("GET /v1.0/me/calendars", func(w http.ResponseWriter, r *http.Request) {
		if !g.auth(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"value": []map[string]any{
			{"id": "cal-1", "name": "Calendar", "isDefaultCalendar": true, "canEdit": true},
			{"id": "cal-2", "name": "Birthdays", "isDefaultCalendar": false, "canEdit": false},
		}})
	})
	mux.HandleFunc("GET /v1.0/me/calendars/{cal}/calendarView", func(w http.ResponseWriter, r *http.Request) {
		if !g.auth(w, r) {
			return
		}
		q := r.URL.Query()
		from, err1 := time.Parse(time.RFC3339, q.Get("startDateTime"))
		to, err2 := time.Parse(time.RFC3339, q.Get("endDateTime"))
		if err1 != nil || err2 != nil {
			http.Error(w, `{"error":{"code":"ErrorInvalidRequest","message":"window"}}`, http.StatusBadRequest)
			return
		}
		if !strings.Contains(q.Get("$expand"), markerID) {
			http.Error(w, `{"error":{"code":"ErrorInvalidRequest","message":"the mark must be expanded"}}`, http.StatusBadRequest)
			return
		}
		g.mu.Lock()
		var all []map[string]any
		for _, id := range g.order {
			e := g.events[id]
			if e["calendar"] != r.PathValue("cal") || e["type"] == "seriesMaster" {
				continue
			}
			s, en := parseGraphTime(dt(e, "start")), parseGraphTime(dt(e, "end"))
			if s.Before(to) && en.After(from) {
				all = append(all, g.wire(e))
			}
		}
		g.mu.Unlock()
		// One page break, so paging is exercised: the first call answers one
		// event and a next link, the next call the rest.
		skip, _ := strconv.Atoi(q.Get("$skip"))
		out := map[string]any{"value": []map[string]any{}}
		if skip == 0 && len(all) > 1 {
			out["value"] = all[:1]
			next := *r.URL
			nq := next.Query()
			nq.Set("$skip", "1")
			next.RawQuery = nq.Encode()
			out["@odata.nextLink"] = g.srv.URL + next.String()
		} else if skip < len(all) {
			out["value"] = all[skip:]
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("GET /v1.0/me/events/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !g.auth(w, r) {
			return
		}
		g.mu.Lock()
		e, ok := g.events[r.PathValue("id")]
		g.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":{"code":"ErrorItemNotFound","message":"gone"}}`, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, g.wire(e))
	})
	mux.HandleFunc("POST /v1.0/me/calendars/{cal}/events", func(w http.ResponseWriter, r *http.Request) {
		if !g.auth(w, r) {
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":{"code":"BadRequest","message":"json"}}`, http.StatusBadRequest)
			return
		}
		if _, has := body["attendees"]; has {
			http.Error(w, `{"error":{"code":"Refused","message":"a proposal must carry no attendees"}}`, http.StatusBadRequest)
			return
		}
		if body["showAs"] != "tentative" || body["responseRequested"] != false {
			http.Error(w, `{"error":{"code":"Refused","message":"a proposal is tentative and asks no response"}}`, http.StatusBadRequest)
			return
		}
		id := g.add(r.PathValue("cal"), body)
		g.mu.Lock()
		e := g.events[id]
		g.mu.Unlock()
		writeJSON(w, http.StatusCreated, g.wire(e))
	})
	mux.HandleFunc("PATCH /v1.0/me/events/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !g.auth(w, r) {
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.mu.Lock()
		e, ok := g.events[r.PathValue("id")]
		if ok {
			for k, v := range body {
				e[k] = v
			}
			g.seq++
			e["changeKey"] = fmt.Sprintf("ck-%d", g.seq)
			g.changes = append(g.changes, e["id"].(string))
		}
		g.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":{"code":"ErrorItemNotFound","message":"gone"}}`, http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, g.wire(e))
	})
	mux.HandleFunc("DELETE /v1.0/me/events/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !g.auth(w, r) {
			return
		}
		g.mu.Lock()
		_, ok := g.events[r.PathValue("id")]
		if ok {
			delete(g.events, r.PathValue("id"))
			g.changes = append(g.changes, "-"+r.PathValue("id"))
		}
		g.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":{"code":"ErrorItemNotFound","message":"gone"}}`, http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1.0/me/calendarView/delta", func(w http.ResponseWriter, r *http.Request) {
		if !g.auth(w, r) {
			return
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.gone {
			g.gone = false
			http.Error(w, `{"error":{"code":"SyncStateNotFound","message":"start again"}}`, http.StatusGone)
			return
		}
		q := r.URL.Query()
		if q.Get("$deltatoken") == "" && (q.Get("startDateTime") == "" || q.Get("endDateTime") == "") {
			http.Error(w, `{"error":{"code":"ErrorInvalidRequest","message":"window"}}`, http.StatusBadRequest)
			return
		}
		seen := len(g.changes)
		if tok := q.Get("$deltatoken"); tok != "" {
			seen, _ = strconv.Atoi(tok)
		}
		var value []map[string]any
		for _, id := range g.changes[min(seen, len(g.changes)):] {
			if strings.HasPrefix(id, "-") {
				value = append(value, map[string]any{"id": id[1:], "@removed": map[string]string{"reason": "deleted"}})
				continue
			}
			if e, ok := g.events[id]; ok {
				value = append(value, map[string]any{"id": id, "changeKey": e["changeKey"], "subject": e["subject"]})
			}
		}
		if value == nil {
			value = []map[string]any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"value":            value,
			"@odata.deltaLink": g.srv.URL + "/v1.0/me/calendarView/delta?$deltatoken=" + strconv.Itoa(len(g.changes)),
		})
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

// add stores an event on a calendar with a fresh id and change key.
func (g *fakeGraph) add(calendar string, e map[string]any) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seq++
	id := fmt.Sprintf("ev-%d", g.seq)
	e["id"] = id
	e["changeKey"] = fmt.Sprintf("ck-%d", g.seq)
	e["calendar"] = calendar
	g.events[id] = e
	g.order = append(g.order, id)
	g.changes = append(g.changes, id)
	return id
}

// wire is the event as Graph would answer it: everything stored but the
// calendar, which Graph does not put on an event.
func (g *fakeGraph) wire(e map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range e {
		if k != "calendar" {
			out[k] = v
		}
	}
	return out
}

func (g *fakeGraph) auth(w http.ResponseWriter, r *http.Request) bool {
	g.mu.Lock()
	g.requests = append(g.requests, r.Method+" "+r.URL.Path)
	g.prefers = append(g.prefers, r.Header.Get("Prefer"))
	ok := r.Header.Get("Authorization") == "Bearer "+g.bearer
	g.mu.Unlock()
	if !ok {
		http.Error(w, `{"error":{"code":"InvalidAuthenticationToken","message":"expired"}}`, http.StatusUnauthorized)
	}
	return ok
}

// dt reads start.dateTime or end.dateTime off a stored event, whether it
// was built here (map[string]string) or decoded from a request
// (map[string]any).
func dt(e map[string]any, k string) string {
	switch v := e[k].(type) {
	case map[string]string:
		return v["dateTime"]
	case map[string]any:
		s, _ := v["dateTime"].(string)
		return s
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
