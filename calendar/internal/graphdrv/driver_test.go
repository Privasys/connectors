// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package graphdrv

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
)

var day = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

func open(t *testing.T, g *fakeGraph) *Driver {
	t.Helper()
	d, err := Open(context.Background(), Config{
		Base: g.srv.URL + "/v1.0", HTTP: g.srv.Client(),
		Token: func(context.Context) (string, error) { return "at-1", nil },
		Now:   func() time.Time { return day },
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return d
}

// Open proves the bearer with /me and the calendar list, reads the
// address, and refuses a bearer Graph refuses.
func TestOpenProvesAndIdentifies(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g)
	if d.User() != "me@example.org" {
		t.Fatalf("user: %q", d.User())
	}
	if d.primary != "cal-1" {
		t.Fatalf("primary: %q", d.primary)
	}
	for _, p := range g.prefers {
		if !strings.Contains(p, `outlook.timezone="UTC"`) || !strings.Contains(p, `outlook.body-content-type="text"`) {
			t.Fatalf("every request prefers UTC and text bodies: %q", p)
		}
	}
	_, err := Open(context.Background(), Config{Base: g.srv.URL + "/v1.0", HTTP: g.srv.Client(),
		Token: func(context.Context) (string, error) { return "stale", nil }})
	if !errors.Is(err, ErrLogin) {
		t.Fatalf("a refused bearer is ErrLogin: %v", err)
	}
}

func TestCalendarsAndEvents(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g)
	cals, err := d.Calendars(context.Background())
	if err != nil || len(cals) != 2 || !cals[0].Primary || cals[0].ReadOnly || !cals[1].ReadOnly {
		t.Fatalf("calendars: %+v %v", cals, err)
	}
	evs, err := d.Events(context.Background(), "", day, day.AddDate(0, 0, 7))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 {
		t.Fatalf("want three events across both calendars and both pages, got %d: %+v", len(evs), evs)
	}
	// Soonest first, across calendars.
	if evs[0].Title != "Bob's birthday" || !evs[0].AllDay || !evs[0].Free || evs[0].Calendar != "cal-2" {
		t.Errorf("the all-day free event first: %+v", evs[0])
	}
	board := evs[1]
	if board.Title != "Board meeting" || board.Location != "Room 4" || board.ConferenceLink != "https://teams.example/join/1" || board.Free || board.Host {
		t.Errorf("board: %+v", board)
	}
	if len(board.Attendees) != 2 || board.Attendees[0].Address != "alice@example.org" || board.Attendees[0].Status != "accepted" || board.Attendees[1].Status != "tentative" {
		t.Errorf("attendees: %+v", board.Attendees)
	}
	if board.Organiser == nil || board.Organiser.Address != "alice@example.org" {
		t.Errorf("organiser: %+v", board.Organiser)
	}
	if strings.Contains(board.Description, "483920") || board.Redactions != 1 {
		t.Errorf("the code in the body is redacted: %q (%d)", board.Description, board.Redactions)
	}
	if !board.Start.Equal(day.Add(9*time.Hour)) || !board.End.Equal(day.Add(11*time.Hour)) {
		t.Errorf("times: %s %s", board.Start, board.End)
	}
	standup := evs[2]
	if standup.Recurrence != "every week on Monday and Wednesday, until 2026-12-31" || !standup.Host {
		t.Errorf("the rule comes from the series master: %+v", standup)
	}
	// One calendar narrows the view.
	evs, err = d.Events(context.Background(), "cal-2", day, day.AddDate(0, 0, 7))
	if err != nil || len(evs) != 1 {
		t.Fatalf("one calendar: %+v %v", evs, err)
	}
	if _, err := d.Events(context.Background(), "", day, day.AddDate(0, 0, 90)); err == nil {
		t.Fatal("a window over the bound is refused")
	}
}

func TestGetStaleAndMissing(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g)
	evs, _ := d.Events(context.Background(), "cal-1", day, day.AddDate(0, 0, 7))
	got, err := d.Get(context.Background(), evs[0].ID)
	if err != nil || got.Title != evs[0].Title || got.ID != evs[0].ID {
		t.Fatalf("get: %+v %v", got, err)
	}
	// The event changes behind the listing: the id is stale.
	g.mu.Lock()
	g.events["ev-1"]["changeKey"] = "moved"
	g.mu.Unlock()
	if _, err := d.Get(context.Background(), evs[0].ID); !errors.Is(err, cal.ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	if _, err := d.Get(context.Background(), eventRef{cal: "cal-1", id: "nope"}.encode()); !errors.Is(err, cal.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := d.Get(context.Background(), "not-an-id!"); !errors.Is(err, cal.ErrBadID) {
		t.Fatalf("bad id: %v", err)
	}
}

// A proposal goes to Graph tentative, asking no response, with no
// attendees and the mark; it can be updated and deleted, and nothing else
// can.
func TestProposeUpdateDeleteOnlyTheMarked(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g)
	ev, err := d.Propose(context.Background(), "", cal.Proposal{
		Title: "Lunch", Description: "Catch up", Location: "Cafe", Start: day.Add(12 * time.Hour), End: day.Add(13 * time.Hour),
		Attendees: []string{"alice@example.org", " Bob "}, Ref: "run-1",
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if !ev.Proposed || ev.ProposedBy != "run-1" || ev.Status != "tentative" || ev.Calendar != "cal-1" || len(ev.Attendees) != 0 {
		t.Fatalf("the proposal as read back: %+v", ev)
	}
	if ev.Description != "Catch up\n\nProposed attendees: alice@example.org, Bob" {
		t.Fatalf("the people are in the text: %q", ev.Description)
	}
	g.mu.Lock()
	stored := g.events["ev-4"]
	g.mu.Unlock()
	if stored["showAs"] != "tentative" || stored["responseRequested"] != false || stored["attendees"] != nil {
		t.Fatalf("stored: %+v", stored)
	}
	// An all-day proposal.
	allDay, err := d.Propose(context.Background(), "cal-1", cal.Proposal{Title: "Away", Start: day.AddDate(0, 0, 1), End: day.AddDate(0, 0, 3), AllDay: true})
	if err != nil || !allDay.AllDay || !allDay.End.Equal(day.AddDate(0, 0, 3)) {
		t.Fatalf("all-day: %+v %v", allDay, err)
	}

	// Update keeps the mark and the status, rewrites the names paragraph.
	title, desc := "Lunch, moved", "New plan"
	updated, err := d.Update(context.Background(), ev.ID, cal.Patch{Title: &title, Description: &desc, Start: ptr(day.Add(13 * time.Hour)), End: ptr(day.Add(14 * time.Hour))})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Title != title || updated.Description != "New plan\n\nProposed attendees: alice@example.org, Bob" || !updated.Proposed || updated.Status != "tentative" || !updated.Start.Equal(day.Add(13*time.Hour)) {
		t.Fatalf("updated: %+v", updated)
	}
	if updated.ID == ev.ID {
		t.Fatal("an update moves the change key, so the id must move")
	}
	// The old id is stale now.
	if _, err := d.Update(context.Background(), ev.ID, cal.Patch{Title: &title}); !errors.Is(err, cal.ErrStale) {
		t.Fatalf("stale update: %v", err)
	}
	// Replacing the names alone keeps the text.
	updated, err = d.Update(context.Background(), updated.ID, cal.Patch{Attendees: []string{"Carol"}})
	if err != nil || updated.Description != "New plan\n\nProposed attendees: Carol" {
		t.Fatalf("names replaced: %q %v", updated.Description, err)
	}

	// The holder's own event is refused, unread and untouched.
	evs, _ := d.Events(context.Background(), "cal-1", day, day.AddDate(0, 0, 1))
	var theirs cal.Event
	for _, e := range evs {
		if e.Title == "Board meeting" {
			theirs = e
		}
	}
	if _, err := d.Update(context.Background(), theirs.ID, cal.Patch{Title: &title}); !errors.Is(err, cal.ErrNotProposed) {
		t.Fatalf("their event: %v", err)
	}
	if err := d.Delete(context.Background(), theirs.ID); !errors.Is(err, cal.ErrNotProposed) {
		t.Fatalf("their event: %v", err)
	}
	for _, req := range g.requests {
		if strings.HasPrefix(req, "PATCH ") && strings.HasSuffix(req, "/ev-1") || strings.HasPrefix(req, "DELETE ") && strings.HasSuffix(req, "/ev-1") {
			t.Fatalf("the holder's event was written to: %s", req)
		}
	}
	// The proposal can be deleted.
	if err := d.Delete(context.Background(), updated.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := d.Get(context.Background(), updated.ID); !errors.Is(err, cal.ErrNotFound) {
		t.Fatalf("gone: %v", err)
	}
}

func ptr(t time.Time) *time.Time { return &t }

// The feed: the first call is a baseline; a write shows up as a change
// with a fresh id; a removal as removed; a 410 as calendar_changed with a
// fresh cursor; a link that points elsewhere is not followed.
func TestChangesFollowTheDelta(t *testing.T) {
	pollEvery = 10 * time.Millisecond
	t.Cleanup(func() { pollEvery = 20 * time.Second })
	g := newFakeGraph(t)
	d := open(t, g)
	changes, cur, err := d.Changes(context.Background(), "", 0)
	if err != nil || len(changes) != 0 || cur == "" {
		t.Fatalf("baseline: %v %q %v", changes, cur, err)
	}
	if _, err := d.Propose(context.Background(), "", cal.Proposal{Title: "New", Start: day.Add(time.Hour), End: day.Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	changes, cur2, err := d.Changes(context.Background(), cur, 2*time.Second)
	if err != nil || len(changes) != 1 || changes[0].Kind != "changed" || changes[0].Calendar != "cal-1" {
		t.Fatalf("after a proposal: %+v %v", changes, err)
	}
	if got, err := d.Get(context.Background(), changes[0].ID); err != nil || got.Title != "New" {
		t.Fatalf("the change's id is fresh: %+v %v", got, err)
	}
	if err := d.Delete(context.Background(), changes[0].ID); err != nil {
		t.Fatal(err)
	}
	changes, cur3, err := d.Changes(context.Background(), cur2, 2*time.Second)
	if err != nil || len(changes) != 1 || changes[0].Kind != "removed" {
		t.Fatalf("after a delete: %+v %v", changes, err)
	}
	// Nothing happens: the call waits and answers empty with the cursor kept.
	changes, cur4, err := d.Changes(context.Background(), cur3, 30*time.Millisecond)
	if err != nil || len(changes) != 0 || cur4 != cur3 {
		t.Fatalf("quiet: %+v %q %v", changes, cur4, err)
	}
	// Graph forgets the link.
	g.mu.Lock()
	g.gone = true
	g.mu.Unlock()
	changes, cur5, err := d.Changes(context.Background(), cur4, time.Second)
	if err != nil || len(changes) != 1 || changes[0].Kind != "calendar_changed" || cur5 == "" {
		t.Fatalf("after a 410: %+v %q %v", changes, cur5, err)
	}
	// A cursor pointing elsewhere is not a cursor.
	if _, ok := d.decodeCursor(encodeCursor(cursor{V: 1, Link: "https://evil.example/delta", From: day.Unix()})); ok {
		t.Fatal("a link away from Graph must not be followed")
	}
	// An old cursor is re-windowed after being followed.
	old := cursor{V: 1, Link: g.srv.URL + "/v1.0/me/calendarView/delta?$deltatoken=0", From: day.Add(-30 * 24 * time.Hour).Unix()}
	changes, cur6, err := d.Changes(context.Background(), encodeCursor(old), time.Second)
	if err != nil || len(changes) == 0 {
		t.Fatalf("the old link is followed once: %+v %v", changes, err)
	}
	if c, _ := d.decodeCursor(cur6); c.From != day.Unix() {
		t.Fatalf("then minted afresh: %+v", c)
	}
}

func TestRecurrenceText(t *testing.T) {
	for _, c := range []struct {
		r    recurrence
		want string
	}{
		{recurrence{Pattern: recurrencePattern{Type: "daily", Interval: 1}}, "every day"},
		{recurrence{Pattern: recurrencePattern{Type: "daily", Interval: 3}, Range: recurrenceRange{Type: "numbered", NumberOfOccurrences: 5}}, "every 3 days, 5 times"},
		{recurrence{Pattern: recurrencePattern{Type: "weekly", Interval: 2, DaysOfWeek: []string{"tuesday", "thursday"}}}, "every 2 weeks on Tuesday and Thursday"},
		{recurrence{Pattern: recurrencePattern{Type: "absoluteMonthly", Interval: 1, DayOfMonth: 15}}, "every month on day 15"},
		{recurrence{Pattern: recurrencePattern{Type: "relativeMonthly", Interval: 1, Index: "first", DaysOfWeek: []string{"monday"}}}, "every month on the first Monday"},
		{recurrence{Pattern: recurrencePattern{Type: "absoluteYearly", Interval: 1, Month: 12, DayOfMonth: 25}}, "every year on December 25"},
		{recurrence{Pattern: recurrencePattern{Type: "somethingNew"}}, "recurring"},
	} {
		if got := recurrenceText(c.r); got != c.want {
			t.Errorf("%+v: %q, want %q", c.r, got, c.want)
		}
	}
}
