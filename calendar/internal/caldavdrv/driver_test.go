// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package caldavdrv

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
)

var (
	day = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC) // a Monday
	ctx = context.Background()
)

func open(t *testing.T, f *fakeServer) *Driver {
	t.Helper()
	d, err := Open(ctx, Config{
		Endpoint: f.srv.URL + "/.well-known/caldav", User: f.user, Password: f.password, HTTPClient: f.srv.Client(),
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	d.now = func() time.Time { return day }
	return d
}

// Discovery follows the well-known redirect as a PROPFIND, finds the
// principal and the home (given as a full URL), and lists the calendars.
func TestOpenDiscoversTheCalendars(t *testing.T) {
	f := newFakeServer()
	defer f.close()
	d := open(t, f)
	cals, err := d.Calendars(ctx)
	if err != nil || len(cals) != 2 {
		t.Fatalf("calendars: %v %v", cals, err)
	}
	if cals[0].Name != "Personal" || !cals[0].Primary || cals[1].Primary {
		t.Fatalf("the first writable calendar is primary: %+v", cals)
	}
	if _, err := calendarPath(cals[0].ID); err != nil {
		t.Fatalf("calendar ids decode: %v", err)
	}
	for _, want := range []string{"PROPFIND /.well-known/caldav", "PROPFIND /dav/", "PROPFIND /principals/me/", "PROPFIND /cal/me/"} {
		if !contains(f.requests, want) {
			t.Errorf("discovery should have made %q: %v", want, f.requests)
		}
	}
	if contains(f.requests, "GET /dav/") {
		t.Error("the redirect turned the PROPFIND into a GET")
	}
}

func TestOpenRefusesBadCredentials(t *testing.T) {
	f := newFakeServer()
	defer f.close()
	_, err := Open(ctx, Config{Endpoint: f.srv.URL + "/dav/", User: f.user, Password: "wrong", HTTPClient: f.srv.Client()})
	if !errors.Is(err, ErrLogin) {
		t.Fatalf("a refused password is ErrLogin, got %v", err)
	}
}

func TestBearerIsSentWhenATokenIsGiven(t *testing.T) {
	f := newFakeServer()
	defer f.close()
	f.bearer = "tok-1"
	calls := 0
	d, err := Open(ctx, Config{
		Endpoint: f.srv.URL + "/dav/", User: f.user, HTTPClient: f.srv.Client(),
		Token: func(context.Context) (string, error) { calls++; return "tok-1", nil },
	})
	if err != nil || calls == 0 {
		t.Fatalf("open with a bearer: %v (token asked %d times)", err, calls)
	}
	if _, err := d.Calendars(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestEventsInAWindow(t *testing.T) {
	f := newFakeServer()
	defer f.close()
	f.put("/cal/me/personal/", "a.ics", vevent("UID:a", "DTSTAMP:20260101T000000Z",
		"DTSTART:"+ts(day.Add(9*time.Hour)), "DTEND:"+ts(day.Add(10*time.Hour)),
		"SUMMARY:Standup", "LOCATION:https://meet.google.com/abc-defg-hij",
		"ORGANIZER;CN=Me:mailto:ME@example.org",
		"ATTENDEE;CN=Alice;PARTSTAT=ACCEPTED:mailto:alice@example.org",
		"ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:bob@example.org",
		"DESCRIPTION:Agenda. Your verification code is 483920. Dial-in below."))
	f.put("/cal/me/work/", "b.ics", vevent("UID:b", "DTSTAMP:20260101T000000Z",
		"DTSTART;VALUE=DATE:20261006", "DTEND;VALUE=DATE:20261007", "SUMMARY:Offsite",
		"ORGANIZER:mailto:boss@example.org"))
	f.put("/cal/me/work/", "old.ics", vevent("UID:old", "DTSTAMP:20260101T000000Z",
		"DTSTART:20260101T090000Z", "DTEND:20260101T100000Z", "SUMMARY:Long ago"))
	d := open(t, f)

	evs, err := d.Events(ctx, "", day, day.AddDate(0, 0, 7))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want the two events in the window, got %d: %+v", len(evs), evs)
	}
	standup, offsite := evs[0], evs[1]
	if standup.Title != "Standup" || !standup.Host || standup.AllDay || standup.ConferenceLink != "https://meet.google.com/abc-defg-hij" {
		t.Errorf("standup: %+v", standup)
	}
	if len(standup.Attendees) != 2 || standup.Attendees[0].Status != "accepted" || standup.Attendees[0].Name != "Alice" || standup.Attendees[1].Status != "needs-action" {
		t.Errorf("attendees: %+v", standup.Attendees)
	}
	if strings.Contains(standup.Description, "483920") || standup.Redactions != 1 || !strings.Contains(standup.Description, "Agenda") {
		t.Errorf("the description is redacted and otherwise kept: %q (%d)", standup.Description, standup.Redactions)
	}
	if offsite.Title != "Offsite" || !offsite.AllDay || offsite.Host || offsite.Organiser == nil || offsite.Organiser.Address != "boss@example.org" {
		t.Errorf("offsite: %+v", offsite)
	}
	if offsite.End.Sub(offsite.Start) != 24*time.Hour {
		t.Errorf("an all-day event spans its day: %s to %s", offsite.Start, offsite.End)
	}

	// One calendar only.
	work, err := d.Events(ctx, offsite.Calendar, day, day.AddDate(0, 0, 7))
	if err != nil || len(work) != 1 || work[0].Title != "Offsite" {
		t.Fatalf("one calendar: %+v %v", work, err)
	}
	// The window is bounded.
	if _, err := d.Events(ctx, "", day, day.AddDate(0, 3, 0)); err == nil {
		t.Fatal("a three-month window should be refused")
	}
	if _, err := d.Events(ctx, "", day, day); err == nil {
		t.Fatal("an empty window should be refused")
	}
}

func TestRecurringEventsAreExpandedWithOverrides(t *testing.T) {
	f := newFakeServer()
	defer f.close()
	// Weekly on Monday at 09:00, with the second occurrence moved to Tuesday
	// and the third cancelled.
	second := day.AddDate(0, 0, 7).Add(9 * time.Hour)
	third := day.AddDate(0, 0, 14).Add(9 * time.Hour)
	f.put("/cal/me/personal/", "r.ics",
		"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//fake//EN\r\n"+
			"BEGIN:VEVENT\r\nUID:r\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:"+ts(day.Add(9*time.Hour))+"\r\nDTEND:"+ts(day.Add(9*time.Hour+30*time.Minute))+
			"\r\nRRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=5\r\nEXDATE:"+ts(third)+"\r\nSUMMARY:Weekly\r\nEND:VEVENT\r\n"+
			"BEGIN:VEVENT\r\nUID:r\r\nDTSTAMP:20260101T000000Z\r\nRECURRENCE-ID:"+ts(second)+"\r\nDTSTART:"+ts(second.Add(24*time.Hour))+"\r\nDTEND:"+ts(second.Add(24*time.Hour+30*time.Minute))+
			"\r\nSUMMARY:Weekly (moved)\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
	d := open(t, f)

	evs, err := d.Events(ctx, "", day, day.AddDate(0, 0, 28))
	if err != nil {
		t.Fatal(err)
	}
	var titles []string
	for _, ev := range evs {
		titles = append(titles, ev.Start.Format("Mon 02")+" "+ev.Title)
	}
	want := []string{"Mon 05 Weekly", "Tue 13 Weekly (moved)", "Mon 26 Weekly"}
	if strings.Join(titles, "|") != strings.Join(want, "|") {
		t.Fatalf("occurrences = %v, want %v", titles, want)
	}
	if evs[0].Recurrence != "every week on Monday, 5 times" {
		t.Errorf("recurrence text: %q", evs[0].Recurrence)
	}
	// Each occurrence has its own id, and Get finds the one it names.
	if evs[0].ID == evs[2].ID {
		t.Fatal("two occurrences share an id")
	}
	got, err := d.Get(ctx, evs[1].ID)
	if err != nil || got.Title != "Weekly (moved)" || !got.Start.Equal(evs[1].Start) {
		t.Fatalf("Get of an occurrence: %+v %v", got, err)
	}
}

func TestIDsAreVersioned(t *testing.T) {
	f := newFakeServer()
	defer f.close()
	f.put("/cal/me/personal/", "a.ics", vevent("UID:a", "DTSTAMP:20260101T000000Z",
		"DTSTART:"+ts(day.Add(9*time.Hour)), "DTEND:"+ts(day.Add(10*time.Hour)), "SUMMARY:Before"))
	d := open(t, f)
	evs, _ := d.Events(ctx, "", day, day.AddDate(0, 0, 1))
	id := evs[0].ID
	if got, err := d.Get(ctx, id); err != nil || got.Title != "Before" {
		t.Fatalf("Get: %+v %v", got, err)
	}
	// The event changes behind the id.
	f.put("/cal/me/personal/", "a.ics", vevent("UID:a", "DTSTAMP:20260101T000000Z",
		"DTSTART:"+ts(day.Add(9*time.Hour)), "DTEND:"+ts(day.Add(10*time.Hour)), "SUMMARY:After"))
	if _, err := d.Get(ctx, id); !errors.Is(err, cal.ErrStale) {
		t.Fatalf("a stale id must fail, got %v", err)
	}
	if _, err := d.Get(ctx, "not-an-id"); !errors.Is(err, cal.ErrBadID) {
		t.Fatalf("a malformed id: %v", err)
	}
	ref, _ := parseID(id)
	ref.href = "/cal/me/personal/gone.ics"
	if _, err := d.Get(ctx, ref.id()); !errors.Is(err, cal.ErrNotFound) {
		t.Fatalf("a missing event: %v", err)
	}
}

// The calendar's draft: TENTATIVE, marked, no ATTENDEE and no ORGANIZER on
// the wire, the people named in the text only.
func TestProposeWritesATentativeEventWithNoInvitations(t *testing.T) {
	f := newFakeServer()
	defer f.close()
	d := open(t, f)
	ev, err := d.Propose(ctx, "", cal.Proposal{
		Title: "Coffee", Start: day.Add(15 * time.Hour), End: day.Add(15*time.Hour + 30*time.Minute),
		Description: "Catch up.", Attendees: []string{"Alice <alice@example.org>", "bob@example.org"}, Ref: "run-42",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Proposed || ev.ProposedBy != "run-42" || ev.Status != "tentative" || ev.Title != "Coffee" || len(ev.Attendees) != 0 || ev.Organiser != nil {
		t.Fatalf("the proposal as read back: %+v", ev)
	}
	if !strings.Contains(ev.Description, "Proposed attendees: Alice <alice@example.org>, bob@example.org") || !strings.HasPrefix(ev.Description, "Catch up.") {
		t.Fatalf("attendees are in the text: %q", ev.Description)
	}
	// On the wire.
	f.mu.Lock()
	var raw string
	for _, o := range f.cals["/cal/me/personal/"].objects {
		raw = o.data
	}
	f.mu.Unlock()
	for _, never := range []string{"ATTENDEE", "ORGANIZER", "METHOD"} {
		if strings.Contains(raw, never) {
			t.Errorf("a proposal must not carry %s: %s", never, raw)
		}
	}
	for _, want := range []string{"STATUS:TENTATIVE", "X-PRIVASYS-PROPOSED:run-42", "SUMMARY:Coffee"} {
		if !strings.Contains(raw, want) {
			t.Errorf("a proposal must carry %s: %s", want, raw)
		}
	}
	written := false
	for _, r := range f.requests {
		if strings.HasPrefix(r, "PUT /cal/me/personal/") && strings.HasSuffix(r, "@privasys.ics") {
			written = true
		}
	}
	if !written {
		t.Errorf("the object is written under its uid: %v", f.requests)
	}
	// It is listed, on the primary calendar.
	evs, _ := d.Events(ctx, "", day, day.AddDate(0, 0, 1))
	if len(evs) != 1 || evs[0].ID != ev.ID {
		t.Fatalf("the proposal is listed with the same id: %+v", evs)
	}
	if _, err := d.Propose(ctx, "", cal.Proposal{Title: "x", Start: day, End: day}); err == nil {
		t.Fatal("an empty span should be refused")
	}
}

// Only a proposed event may be updated or deleted; the guard is on the
// property, not on who asks.
func TestUpdateAndDeleteOnlyTouchProposals(t *testing.T) {
	f := newFakeServer()
	defer f.close()
	f.put("/cal/me/personal/", "theirs.ics", vevent("UID:theirs", "DTSTAMP:20260101T000000Z",
		"DTSTART:"+ts(day.Add(9*time.Hour)), "DTEND:"+ts(day.Add(10*time.Hour)), "SUMMARY:Theirs"))
	d := open(t, f)
	evs, _ := d.Events(ctx, "", day, day.AddDate(0, 0, 1))
	theirs := evs[0].ID
	title := "Renamed"
	if _, err := d.Update(ctx, theirs, cal.Patch{Title: &title}); !errors.Is(err, cal.ErrNotProposed) {
		t.Fatalf("updating someone's event: %v", err)
	}
	if err := d.Delete(ctx, theirs); !errors.Is(err, cal.ErrNotProposed) {
		t.Fatalf("deleting someone's event: %v", err)
	}

	mine, err := d.Propose(ctx, "", cal.Proposal{Title: "Mine", Start: day.Add(11 * time.Hour), End: day.Add(12 * time.Hour), Attendees: []string{"a@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	later, laterEnd := day.Add(13*time.Hour), day.Add(14*time.Hour)
	updated, err := d.Update(ctx, mine.ID, cal.Patch{Title: &title, Start: &later, End: &laterEnd, Attendees: []string{"b@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Title != "Renamed" || !updated.Start.Equal(later) || updated.Status != "tentative" || !updated.Proposed {
		t.Fatalf("update: %+v", updated)
	}
	if !strings.Contains(updated.Description, "Proposed attendees: b@example.org") || strings.Contains(updated.Description, "a@example.org") {
		t.Fatalf("attendees rewritten: %q", updated.Description)
	}
	if updated.ID == mine.ID {
		t.Fatal("an update yields a fresh id")
	}
	// The old id is stale now, for updating and deleting alike.
	if _, err := d.Update(ctx, mine.ID, cal.Patch{Title: &title}); !errors.Is(err, cal.ErrStale) {
		t.Fatalf("update with a stale id: %v", err)
	}
	if err := d.Delete(ctx, mine.ID); !errors.Is(err, cal.ErrStale) {
		t.Fatalf("delete with a stale id: %v", err)
	}
	if err := d.Delete(ctx, updated.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := d.Get(ctx, updated.ID); !errors.Is(err, cal.ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	// Their event is still there.
	if got, err := d.Get(ctx, theirs); err != nil || got.Title != "Theirs" {
		t.Fatalf("their event was touched: %+v %v", got, err)
	}
}

func TestChangesWithSyncCollection(t *testing.T) {
	f := newFakeServer()
	defer f.close()
	f.put("/cal/me/personal/", "a.ics", vevent("UID:a", "DTSTAMP:20260101T000000Z",
		"DTSTART:"+ts(day.Add(9*time.Hour)), "DTEND:"+ts(day.Add(10*time.Hour)), "SUMMARY:A"))
	d := open(t, f)

	// No cursor: from now, nothing reported.
	changes, cursor, err := d.Changes(ctx, "", 0)
	if err != nil || len(changes) != 0 || cursor == "" {
		t.Fatalf("baseline: %v %q %v", changes, cursor, err)
	}
	// Nothing happened: an empty answer, the same cursor.
	changes, cursor2, err := d.Changes(ctx, cursor, 0)
	if err != nil || len(changes) != 0 || cursor2 != cursor {
		t.Fatalf("quiet: %v %q %v", changes, cursor2, err)
	}

	f.put("/cal/me/personal/", "b.ics", vevent("UID:b", "DTSTAMP:20260101T000000Z",
		"DTSTART:"+ts(day.Add(11*time.Hour)), "DTEND:"+ts(day.Add(12*time.Hour)), "SUMMARY:B"))
	f.mu.Lock()
	c := f.cals["/cal/me/personal/"]
	c.version++
	delete(c.objects, "/cal/me/personal/a.ics")
	c.deleted["/cal/me/personal/a.ics"] = c.version
	f.mu.Unlock()

	changes, cursor3, err := d.Changes(ctx, cursor, 0)
	if err != nil || len(changes) != 2 {
		t.Fatalf("after a write and a delete: %+v %v", changes, err)
	}
	if changes[0].Kind != "changed" || changes[1].Kind != "removed" {
		t.Fatalf("kinds: %+v", changes)
	}
	if got, err := d.Get(ctx, changes[0].ID); err != nil || got.Title != "B" {
		t.Fatalf("a change's id is a usable event id: %+v %v", got, err)
	}
	if cursor3 == cursor {
		t.Fatal("the cursor should move")
	}
	// The window is held: a change during the wait wakes the call.
	go func() {
		time.Sleep(30 * time.Millisecond)
		f.put("/cal/me/work/", "c.ics", vevent("UID:c", "DTSTAMP:20260101T000000Z",
			"DTSTART:"+ts(day.Add(14*time.Hour)), "DTEND:"+ts(day.Add(15*time.Hour)), "SUMMARY:C"))
	}()
	prev := pollEvery
	pollEvery = 10 * time.Millisecond
	defer func() { pollEvery = prev }()
	start := time.Now()
	changes, _, err = d.Changes(ctx, cursor3, 5*time.Second)
	if err != nil || len(changes) != 1 || changes[0].Kind != "changed" {
		t.Fatalf("held call: %+v %v", changes, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("the held call did not wake on the change")
	}
	// A cursor from another release, or garbage, is "from now".
	if _, c, err := d.Changes(ctx, "garbage", 0); err != nil || c == "" {
		t.Fatalf("a bad cursor is a fresh start: %v", err)
	}
}

func TestChangesFallBackToCTags(t *testing.T) {
	f := newFakeServer()
	defer f.close()
	f.noSync = true
	d := open(t, f)
	_, cursor, err := d.Changes(ctx, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	f.put("/cal/me/work/", "x.ics", vevent("UID:x", "DTSTAMP:20260101T000000Z",
		"DTSTART:"+ts(day.Add(9*time.Hour)), "DTEND:"+ts(day.Add(10*time.Hour)), "SUMMARY:X"))
	changes, cursor2, err := d.Changes(ctx, cursor, 0)
	if err != nil || len(changes) != 1 || changes[0].Kind != "calendar_changed" || changes[0].ID != "" {
		t.Fatalf("ctag fallback: %+v %v", changes, err)
	}
	if p, _ := calendarPath(changes[0].Calendar); p != "/cal/me/work/" {
		t.Fatalf("the changed calendar is named: %+v", changes[0])
	}
	if changes, _, err := d.Changes(ctx, cursor2, 0); err != nil || len(changes) != 0 {
		t.Fatalf("quiet again: %+v %v", changes, err)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
