// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package caldavdrv

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
	"github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
)

func TestEventIDsRoundTripAndRefuseTampering(t *testing.T) {
	ref := eventRef{cal: "/cal/me/personal/", href: "/cal/me/personal/a.ics", etag: "e7", instance: "2026-10-05T09:00:00Z"}
	got, err := parseID(ref.id())
	if err != nil || got != ref {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, bad := range []string{"", "!!!", "AAAA", strings.Repeat("A", 40)} {
		if _, err := parseID(bad); !errors.Is(err, cal.ErrBadID) {
			t.Errorf("parseID(%q) = %v, want ErrBadID", bad, err)
		}
	}
	if _, err := calendarPath("bm90LWEtcGF0aA"); err == nil {
		t.Error("a calendar id that is not a path should be refused")
	}
	if p, err := calendarPath(calendarID("/cal/me/work/")); err != nil || p != "/cal/me/work/" {
		t.Errorf("calendar id round trip: %q %v", p, err)
	}
}

func TestRecurrenceText(t *testing.T) {
	for rule, want := range map[string]string{
		"FREQ=WEEKLY;BYDAY=MO,WE":                  "every week on Monday and Wednesday",
		"FREQ=DAILY;INTERVAL=2;COUNT=10":           "every 2 days, 10 times",
		"FREQ=MONTHLY;BYDAY=-1FR":                  "every month on the last Friday",
		"FREQ=MONTHLY;BYMONTHDAY=15":               "every month on day 15",
		"FREQ=YEARLY;UNTIL=20271231T000000Z":       "every year, until 2027-12-31",
		"FREQ=WEEKLY;INTERVAL=3;BYDAY=2TU;COUNT=2": "every 3 weeks on the second Tuesday, 2 times",
	} {
		opt, err := rrule.StrToROption(rule)
		if err != nil {
			t.Fatal(err)
		}
		if got := recurrenceText(opt); got != want {
			t.Errorf("%s: %q, want %q", rule, got, want)
		}
	}
}

func TestConferenceLinkAndParticipants(t *testing.T) {
	c := ical.NewEvent()
	c.Props.SetText(ical.PropDescription, "Join at https://us02web.zoom.us/j/123456?pwd=abc and bring a pen.")
	if got := conferenceLink(c.Component); got != "https://us02web.zoom.us/j/123456?pwd=abc" {
		t.Errorf("link in text: %q", got)
	}
	p := ical.NewProp(ical.PropConference)
	p.Value = "https://meet.example/room"
	c.Props.Set(p)
	if got := conferenceLink(c.Component); got != "https://meet.example/room" {
		t.Errorf("CONFERENCE wins: %q", got)
	}
	a := ical.NewProp(ical.PropAttendee)
	a.Value = "MAILTO:Alice@Example.org"
	a.Params.Set("PARTSTAT", "TENTATIVE")
	a.Params.Set("CN", "Alice")
	c.Props.Add(a)
	attendees, organiser := participants(c.Component)
	if len(attendees) != 1 || attendees[0].Address != "alice@example.org" || attendees[0].Status != "tentative" || attendees[0].Name != "Alice" || organiser != nil {
		t.Errorf("participants: %+v %+v", attendees, organiser)
	}
}

func TestProposalDescriptionComposition(t *testing.T) {
	if got := composeDescription("  Notes. ", []string{"a@x", "b@y"}); got != "Notes.\n\nProposed attendees: a@x, b@y" {
		t.Errorf("compose: %q", got)
	}
	if got := composeDescription("", []string{"a@x"}); got != "Proposed attendees: a@x" {
		t.Errorf("compose without text: %q", got)
	}
	if got := baseDescription("Notes.\n\nProposed attendees: a@x, b@y"); got != "Notes." {
		t.Errorf("base: %q", got)
	}
	if got := baseDescription("Proposed attendees: a@x"); got != "" {
		t.Errorf("base without text: %q", got)
	}
	obj, uid := newProposal(cal.Proposal{
		Title: "T", Start: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), AllDay: true, Ref: "r",
	}, time.Now())
	if !strings.HasSuffix(uid, "@privasys") {
		t.Errorf("uid: %q", uid)
	}
	ev := obj.Events()[0]
	if st := ev.Props.Get(ical.PropDateTimeStart); st == nil || st.ValueType() != ical.ValueDate || st.Value != "20261005" {
		t.Errorf("an all-day proposal is a DATE: %+v", st)
	}
	if ev.Props.Get(ical.PropAttendee) != nil || ev.Props.Get(ical.PropOrganizer) != nil {
		t.Error("a proposal must not carry ATTENDEE or ORGANIZER")
	}
}
