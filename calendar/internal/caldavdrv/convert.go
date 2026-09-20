// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package caldavdrv

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
	"github.com/Privasys/connectors/sdk/redact"
	"github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
)

// object is one calendar resource as fetched: where it lives, which version,
// and what it says.
type object struct {
	cal  string
	href string
	etag string
	data *ical.Calendar
}

// occurrences expands an object into the occurrences that overlap [from,
// to). A one-off is itself; a recurring event is each instance the rule
// produces in the window, with the overrides (RECURRENCE-ID) the object
// carries applied; an override moved into the window from outside it is
// included too. self is the holder's address, for Host.
func occurrences(o object, from, to time.Time, self string) []cal.Event {
	if o.data == nil {
		return nil
	}
	var master *ical.Event
	overrides := map[int64]ical.Event{}
	for _, e := range o.data.Events() {
		e := e
		if rid := e.Props.Get(ical.PropRecurrenceID); rid != nil {
			if t, err := rid.DateTime(time.UTC); err == nil {
				overrides[t.UTC().Unix()] = e
				continue
			}
		}
		if master == nil {
			master = &e
		}
	}
	var out []cal.Event
	keep := func(ev cal.Event) {
		if ev.Start.Before(to) && ev.End.After(from) {
			out = append(out, ev)
		}
	}

	if master != nil {
		start, end, allDay, ok := span(master)
		if ok {
			set, err := master.RecurrenceSet(time.UTC)
			if err != nil || set == nil {
				// A one-off, or a rule this driver cannot read: the event as
				// written, once.
				keep(eventFrom(*master, o, start, end, allDay, "", self))
			} else {
				dur := end.Sub(start)
				for _, occ := range set.Between(from.Add(-dur), to, true) {
					key := occ.UTC().Unix()
					if ov, ok := overrides[key]; ok {
						delete(overrides, key)
						if s, e, ad, ok := span(&ov); ok {
							keep(eventFrom(ov, o, s, e, ad, occ.UTC().Format(time.RFC3339), self))
						}
						continue
					}
					ev := eventFrom(*master, o, occ, occ.Add(dur), allDay, occ.UTC().Format(time.RFC3339), self)
					keep(ev)
				}
			}
		}
	}
	// Overrides the rule did not produce (moved in from outside the window,
	// or an object with overrides and no master).
	for key, ov := range overrides {
		if s, e, ad, ok := span(&ov); ok {
			keep(eventFrom(ov, o, s, e, ad, time.Unix(key, 0).UTC().Format(time.RFC3339), self))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// span reads the start and end of a VEVENT. A DATE start is an all-day
// event; a missing end is the start plus the duration, or one day.
func span(e *ical.Event) (start, end time.Time, allDay bool, ok bool) {
	sp := e.Props.Get(ical.PropDateTimeStart)
	if sp == nil {
		return time.Time{}, time.Time{}, false, false
	}
	start, err := sp.DateTime(time.UTC)
	if err != nil {
		return time.Time{}, time.Time{}, false, false
	}
	allDay = sp.ValueType() == ical.ValueDate || (sp.ValueType() == ical.ValueDefault && len(sp.Value) == 8)
	end, err = e.DateTimeEnd(time.UTC)
	if err != nil || !end.After(start) {
		if allDay {
			end = start.Add(24 * time.Hour)
		} else {
			end = start
		}
	}
	return start, end, allDay, true
}

// eventFrom builds the agent's view of one occurrence.
func eventFrom(e ical.Event, o object, start, end time.Time, allDay bool, instance string, self string) cal.Event {
	ev := cal.Event{
		ID:       eventRef{cal: o.cal, href: o.href, etag: o.etag, instance: instance}.id(),
		Calendar: calendarID(o.cal),
		Start:    start, End: end, AllDay: allDay,
	}
	ev.Title, _ = e.Props.Text(ical.PropSummary)
	ev.Location, _ = e.Props.Text(ical.PropLocation)
	if desc, _ := e.Props.Text(ical.PropDescription); desc != "" {
		r := redact.Apply(desc)
		ev.Description, ev.Redactions = r.Text, r.Count
	}
	if st, err := e.Status(); err == nil && st != "" {
		ev.Status = strings.ToLower(string(st))
	}
	if tr, _ := e.Props.Text(ical.PropTransparency); strings.EqualFold(tr, "TRANSPARENT") {
		ev.Free = true
	}
	ev.Attendees, ev.Organiser = participants(e.Component)
	self = strings.ToLower(strings.TrimSpace(self))
	ev.Host = ev.Organiser == nil || (self != "" && strings.EqualFold(ev.Organiser.Address, self))
	ev.ConferenceLink = conferenceLink(e.Component)
	if rule, err := e.Props.RecurrenceRule(); err == nil && rule != nil {
		ev.Recurrence = recurrenceText(rule)
	}
	if p := e.Props.Get(cal.ProposedProp); p != nil {
		ev.Proposed = true
		ev.ProposedBy = p.Value
	}
	return ev
}

// participants reads ATTENDEE and ORGANIZER. Names are advisory; the address
// is what identifies anyone.
func participants(c *ical.Component) ([]cal.Attendee, *cal.Attendee) {
	var attendees []cal.Attendee
	for _, p := range c.Props.Values(ical.PropAttendee) {
		a := cal.Attendee{Name: p.Params.Get("CN"), Address: mailto(p.Value)}
		switch strings.ToUpper(p.Params.Get("PARTSTAT")) {
		case "ACCEPTED":
			a.Status = "accepted"
		case "DECLINED":
			a.Status = "declined"
		case "TENTATIVE":
			a.Status = "tentative"
		case "NEEDS-ACTION", "":
			a.Status = "needs-action"
		default:
			a.Status = strings.ToLower(p.Params.Get("PARTSTAT"))
		}
		attendees = append(attendees, a)
	}
	var organiser *cal.Attendee
	if p := c.Props.Get(ical.PropOrganizer); p != nil {
		organiser = &cal.Attendee{Name: p.Params.Get("CN"), Address: mailto(p.Value)}
	}
	return attendees, organiser
}

func mailto(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 7 && strings.EqualFold(v[:7], "mailto:") {
		v = v[7:]
	}
	return strings.ToLower(v)
}

// conferenceRe finds a meeting link in free text, for events whose provider
// does not set CONFERENCE.
var conferenceRe = regexp.MustCompile(`https?://(?:meet\.google\.com|[\w.-]*zoom\.us|teams\.microsoft\.com|teams\.live\.com|[\w.-]*webex\.com|meet\.jit\.si|[\w.-]*whereby\.com)/[^\s<>"']+`)

// conferenceLink is the meeting link: the CONFERENCE property (RFC 7986),
// Google's own, or the first known meeting URL in the location, the URL or
// the description.
func conferenceLink(c *ical.Component) string {
	if p := c.Props.Get(ical.PropConference); p != nil && strings.TrimSpace(p.Value) != "" {
		return strings.TrimSpace(p.Value)
	}
	if p := c.Props.Get("X-GOOGLE-CONFERENCE"); p != nil && strings.TrimSpace(p.Value) != "" {
		return strings.TrimSpace(p.Value)
	}
	for _, name := range []string{ical.PropLocation, ical.PropURL, ical.PropDescription} {
		if p := c.Props.Get(name); p != nil {
			if m := conferenceRe.FindString(p.Value); m != "" {
				return m
			}
		}
	}
	return ""
}

var weekdayNames = []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}

// recurrenceText is a sentence about a rule: "every week on Monday and
// Wednesday, until 2026-12-31". Enough for an agent to say it; the rule
// itself stays with the provider.
func recurrenceText(r *rrule.ROption) string {
	unit := map[rrule.Frequency]string{
		rrule.YEARLY: "year", rrule.MONTHLY: "month", rrule.WEEKLY: "week", rrule.DAILY: "day",
		rrule.HOURLY: "hour", rrule.MINUTELY: "minute", rrule.SECONDLY: "second",
	}[r.Freq]
	if unit == "" {
		return "recurring"
	}
	var b strings.Builder
	if r.Interval > 1 {
		fmt.Fprintf(&b, "every %d %ss", r.Interval, unit)
	} else {
		fmt.Fprintf(&b, "every %s", unit)
	}
	if len(r.Byweekday) > 0 {
		var days []string
		for _, d := range r.Byweekday {
			name := "day"
			if i := d.Day(); i >= 0 && i < len(weekdayNames) {
				name = weekdayNames[i]
			}
			if n := d.N(); n != 0 {
				name = fmt.Sprintf("the %s %s", ordinal(n), name)
			}
			days = append(days, name)
		}
		b.WriteString(" on " + strings.Join(days, " and "))
	}
	if len(r.Bymonthday) > 0 {
		var days []string
		for _, d := range r.Bymonthday {
			days = append(days, fmt.Sprintf("day %d", d))
		}
		b.WriteString(" on " + strings.Join(days, " and "))
	}
	if r.Count > 0 {
		fmt.Fprintf(&b, ", %d times", r.Count)
	}
	if !r.Until.IsZero() {
		fmt.Fprintf(&b, ", until %s", r.Until.Format("2006-01-02"))
	}
	return b.String()
}

func ordinal(n int) string {
	switch n {
	case 1:
		return "first"
	case 2:
		return "second"
	case 3:
		return "third"
	case 4:
		return "fourth"
	case -1:
		return "last"
	}
	return fmt.Sprintf("%dth", n)
}

// ---------------------------------------------------------------- writing

// attendeesProp keeps the proposed attendees as data beside the text, so an
// update can rewrite the paragraph without parsing it. Never ATTENDEE: that
// is the property a server sends invitations for.
const attendeesProp = "X-PRIVASYS-PROPOSED-TO"

const attendeesLead = "Proposed attendees: "

// composeDescription puts the attendees into the text, where the holder
// reads them, as the last paragraph.
func composeDescription(base string, attendees []string) string {
	base = strings.TrimSpace(base)
	if len(attendees) == 0 {
		return base
	}
	line := attendeesLead + strings.Join(attendees, ", ")
	if base == "" {
		return line
	}
	return base + "\n\n" + line
}

// baseDescription is the text without the attendees paragraph.
func baseDescription(desc string) string {
	if i := strings.LastIndex(desc, "\n\n"+attendeesLead); i >= 0 {
		return desc[:i]
	}
	if strings.HasPrefix(desc, attendeesLead) {
		return ""
	}
	return desc
}

func cleanAttendees(in []string) []string {
	var out []string
	for _, a := range in {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// newProposal is the calendar object for a proposal: one VEVENT, TENTATIVE,
// marked as the assistant's, with no ATTENDEE and no ORGANIZER so that no
// server anywhere sends an invitation for it.
func newProposal(p cal.Proposal, now time.Time) (*ical.Calendar, string) {
	c := ical.NewCalendar()
	c.Props.SetText(ical.PropVersion, "2.0")
	c.Props.SetText(ical.PropProductID, "-//Privasys//Calendar Connector//EN")
	e := ical.NewEvent()
	uid := newUID()
	e.Props.SetText(ical.PropUID, uid)
	e.Props.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	setSpan(e, p.Start, p.End, p.AllDay)
	e.Props.SetText(ical.PropSummary, p.Title)
	attendees := cleanAttendees(p.Attendees)
	if desc := composeDescription(p.Description, attendees); desc != "" {
		e.Props.SetText(ical.PropDescription, desc)
	}
	if len(attendees) > 0 {
		prop := ical.NewProp(attendeesProp)
		prop.SetTextList(attendees)
		e.Props.Set(prop)
	}
	if strings.TrimSpace(p.Location) != "" {
		e.Props.SetText(ical.PropLocation, strings.TrimSpace(p.Location))
	}
	e.SetStatus(ical.EventTentative)
	mark := ical.NewProp(cal.ProposedProp)
	mark.Value = p.Ref
	e.Props.Set(mark)
	c.Children = append(c.Children, e.Component)
	return c, uid
}

func setSpan(e *ical.Event, start, end time.Time, allDay bool) {
	if allDay {
		e.Props.SetDate(ical.PropDateTimeStart, start)
		e.Props.SetDate(ical.PropDateTimeEnd, end)
		return
	}
	e.Props.SetDateTime(ical.PropDateTimeStart, start.UTC())
	e.Props.SetDateTime(ical.PropDateTimeEnd, end.UTC())
}

// applyPatch changes a proposed event in place. The status stays TENTATIVE
// and the mark stays: an update does not turn a proposal into a booking.
func applyPatch(e *ical.Event, p cal.Patch, now time.Time) {
	if p.Title != nil {
		e.Props.SetText(ical.PropSummary, *p.Title)
	}
	if p.Location != nil {
		if strings.TrimSpace(*p.Location) == "" {
			e.Props.Del(ical.PropLocation)
		} else {
			e.Props.SetText(ical.PropLocation, strings.TrimSpace(*p.Location))
		}
	}
	if p.Start != nil || p.End != nil {
		start, end, allDay, _ := span(e)
		if p.Start != nil {
			start = *p.Start
		}
		if p.End != nil {
			end = *p.End
		}
		e.Props.Del(ical.PropDuration)
		setSpan(e, start, end, allDay && p.Start == nil && p.End == nil)
	}
	if p.Description != nil || p.Attendees != nil {
		desc, _ := e.Props.Text(ical.PropDescription)
		base := baseDescription(desc)
		if p.Description != nil {
			base = *p.Description
		}
		var attendees []string
		if ap := e.Props.Get(attendeesProp); ap != nil {
			attendees, _ = ap.TextList()
		}
		if p.Attendees != nil {
			attendees = cleanAttendees(p.Attendees)
		}
		if composed := composeDescription(base, attendees); composed != "" {
			e.Props.SetText(ical.PropDescription, composed)
		} else {
			e.Props.Del(ical.PropDescription)
		}
		if len(attendees) > 0 {
			prop := ical.NewProp(attendeesProp)
			prop.SetTextList(attendees)
			e.Props.Set(prop)
		} else {
			e.Props.Del(attendeesProp)
		}
	}
	e.Props.SetDateTime(ical.PropDateTimeStamp, now.UTC())
	n := 0
	if seq := e.Props.Get(ical.PropSequence); seq != nil {
		n, _ = seq.Int()
	}
	e.Props.SetText(ical.PropSequence, fmt.Sprint(n+1))
	e.SetStatus(ical.EventTentative)
}

func newUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + "@privasys"
}
