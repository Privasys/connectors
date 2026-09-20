// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package graphdrv

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
	"github.com/Privasys/connectors/sdk/redact"
)

// The mark this connector leaves on a proposal, as a single-value extended
// property: Graph keeps it on the event where no client shows it and no
// invitation carries it. The value is a small JSON document with the run
// id and the people the proposal is for, so an update can rewrite the
// paragraph of names without parsing it. Only an event carrying this mark
// may be updated or deleted here.
const markerID = "String {6f0a0c9e-2a5b-4a3c-9d1e-7b8c5f4a2d10} Name " + cal.ProposedProp

// marker is what the mark's value holds.
type marker struct {
	Ref string   `json:"ref"`
	To  []string `json:"to,omitempty"`
}

func (m marker) encode() string {
	b, _ := json.Marshal(m)
	return string(b)
}

func decodeMarker(s string) (marker, bool) {
	var m marker
	if err := json.Unmarshal([]byte(s), &m); err != nil || m.Ref == "" {
		return marker{}, false
	}
	return m, true
}

// The fields every listing asks for, and the expansion that brings the
// mark back with the event.
const (
	eventSelect = "id,changeKey,subject,body,start,end,isAllDay,location,attendees,organizer,isOrganizer," +
		"isCancelled,showAs,onlineMeeting,onlineMeetingUrl,isOnlineMeeting,type,seriesMasterId,recurrence"
	eventExpand = "singleValueExtendedProperties($filter=id eq '" + markerID + "')"
)

// Graph's shapes, the fields this driver reads.
type (
	dateTimeZone struct {
		DateTime string `json:"dateTime"`
		TimeZone string `json:"timeZone"`
	}
	emailAddress struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	}
	recipient struct {
		EmailAddress emailAddress `json:"emailAddress"`
	}
	attendee struct {
		EmailAddress emailAddress `json:"emailAddress"`
		Status       *struct {
			Response string `json:"response"`
		} `json:"status"`
	}
	extendedProperty struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	recurrencePattern struct {
		Type       string   `json:"type"`
		Interval   int      `json:"interval"`
		DaysOfWeek []string `json:"daysOfWeek"`
		DayOfMonth int      `json:"dayOfMonth"`
		Index      string   `json:"index"`
		Month      int      `json:"month"`
	}
	recurrenceRange struct {
		Type                string `json:"type"`
		EndDate             string `json:"endDate"`
		NumberOfOccurrences int    `json:"numberOfOccurrences"`
	}
	recurrence struct {
		Pattern recurrencePattern `json:"pattern"`
		Range   recurrenceRange   `json:"range"`
	}
	event struct {
		ID        string `json:"id"`
		ChangeKey string `json:"changeKey"`
		Subject   string `json:"subject"`
		Body      *struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"body"`
		Start    dateTimeZone `json:"start"`
		End      dateTimeZone `json:"end"`
		IsAllDay bool         `json:"isAllDay"`
		Location *struct {
			DisplayName string `json:"displayName"`
		} `json:"location"`
		Attendees     []attendee `json:"attendees"`
		Organizer     *recipient `json:"organizer"`
		IsOrganizer   bool       `json:"isOrganizer"`
		IsCancelled   bool       `json:"isCancelled"`
		ShowAs        string     `json:"showAs"`
		IsOnline      bool       `json:"isOnlineMeeting"`
		OnlineMeeting *struct {
			JoinURL string `json:"joinUrl"`
		} `json:"onlineMeeting"`
		OnlineMeetingURL string             `json:"onlineMeetingUrl"`
		Type             string             `json:"type"`
		SeriesMasterID   string             `json:"seriesMasterId"`
		Recurrence       *recurrence        `json:"recurrence"`
		Extended         []extendedProperty `json:"singleValueExtendedProperties"`
		// Removed is set on a delta entry for an event that went.
		Removed *struct {
			Reason string `json:"reason"`
		} `json:"@removed"`
	}
	calendarItem struct {
		ID                string `json:"id"`
		Name              string `json:"name"`
		IsDefaultCalendar bool   `json:"isDefaultCalendar"`
		CanEdit           bool   `json:"canEdit"`
	}
	page struct {
		Value     []event `json:"value"`
		NextLink  string  `json:"@odata.nextLink"`
		DeltaLink string  `json:"@odata.deltaLink"`
	}
)

// parseGraphTime reads Graph's timestamps: RFC 3339 with up to seven
// fractional digits, with or without a zone. A calendar time comes back in
// UTC by the Prefer header and carries none.
func parseGraphTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.9999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// graphTime writes a time the way Graph reads one, in UTC.
func graphTime(t time.Time) dateTimeZone {
	return dateTimeZone{DateTime: t.UTC().Format("2006-01-02T15:04:05"), TimeZone: "UTC"}
}

// mark reads this connector's mark off an event, if it carries one.
func (e event) mark() (marker, bool) {
	for _, p := range e.Extended {
		if p.ID == markerID {
			return decodeMarker(p.Value)
		}
	}
	return marker{}, false
}

// convert builds the agent's view of one event or occurrence. self is the
// holder's address, which is how "the holder is the host" is told from the
// organiser when Graph does not say.
func convert(e event, calendarID, self string) cal.Event {
	ev := cal.Event{
		ID:       eventRef{cal: calendarID, id: e.ID, changeKey: e.ChangeKey}.encode(),
		Calendar: calendarID,
		Title:    strings.TrimSpace(e.Subject),
		Start:    parseGraphTime(e.Start.DateTime),
		End:      parseGraphTime(e.End.DateTime),
		AllDay:   e.IsAllDay,
	}
	if e.IsAllDay {
		ev.Start = truncateDay(ev.Start)
		ev.End = truncateDay(ev.End)
		if !ev.End.After(ev.Start) {
			ev.End = ev.Start.Add(24 * time.Hour)
		}
	}
	if e.Location != nil {
		ev.Location = strings.TrimSpace(e.Location.DisplayName)
	}
	if e.Body != nil && strings.TrimSpace(e.Body.Content) != "" {
		text := e.Body.Content
		if strings.EqualFold(e.Body.ContentType, "html") {
			text = stripHTML(text)
		}
		r := redact.Apply(strings.TrimSpace(text))
		ev.Description, ev.Redactions = r.Text, r.Count
	}
	for _, a := range e.Attendees {
		if a.EmailAddress.Address == "" && a.EmailAddress.Name == "" {
			continue
		}
		at := cal.Attendee{Name: a.EmailAddress.Name, Address: strings.ToLower(a.EmailAddress.Address), Status: "needs-action"}
		if a.Status != nil {
			switch a.Status.Response {
			case "accepted", "organizer":
				at.Status = "accepted"
			case "declined":
				at.Status = "declined"
			case "tentativelyAccepted":
				at.Status = "tentative"
			}
		}
		ev.Attendees = append(ev.Attendees, at)
	}
	if e.Organizer != nil && (e.Organizer.EmailAddress.Address != "" || e.Organizer.EmailAddress.Name != "") {
		ev.Organiser = &cal.Attendee{Name: e.Organizer.EmailAddress.Name, Address: strings.ToLower(e.Organizer.EmailAddress.Address)}
	}
	self = strings.ToLower(strings.TrimSpace(self))
	ev.Host = e.IsOrganizer || ev.Organiser == nil || (self != "" && strings.EqualFold(ev.Organiser.Address, self))
	if e.OnlineMeeting != nil && e.OnlineMeeting.JoinURL != "" {
		ev.ConferenceLink = e.OnlineMeeting.JoinURL
	} else if e.OnlineMeetingURL != "" {
		ev.ConferenceLink = e.OnlineMeetingURL
	}
	switch {
	case e.IsCancelled:
		ev.Status = "cancelled"
	case e.ShowAs == "tentative":
		ev.Status = "tentative"
	default:
		ev.Status = "confirmed"
	}
	// Busy time is what shows as busy, tentative or out of office; free,
	// working elsewhere and unknown do not block.
	switch e.ShowAs {
	case "busy", "tentative", "oof":
	default:
		ev.Free = true
	}
	if e.Recurrence != nil {
		ev.Recurrence = recurrenceText(*e.Recurrence)
	}
	if m, ok := e.mark(); ok {
		ev.Proposed = true
		ev.ProposedBy = m.Ref
	}
	return ev
}

func truncateDay(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// stripHTML is the fallback for a body Graph would not hand over as text:
// tags dropped, entities left to the reader, which is enough for a
// description an agent searches.
func stripHTML(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>':
			in = false
			b.WriteByte(' ')
		case !in:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

var weekdayNames = map[string]string{
	"monday": "Monday", "tuesday": "Tuesday", "wednesday": "Wednesday", "thursday": "Thursday",
	"friday": "Friday", "saturday": "Saturday", "sunday": "Sunday",
}

// recurrenceText says Graph's pattern as a sentence: "every week on
// Monday", "every 2 weeks on Tuesday and Thursday, until 2026-12-31".
func recurrenceText(r recurrence) string {
	p := r.Pattern
	interval := p.Interval
	if interval < 1 {
		interval = 1
	}
	unit := func(one, many string) string {
		if interval == 1 {
			return "every " + one
		}
		return fmt.Sprintf("every %d %s", interval, many)
	}
	var days []string
	for _, d := range p.DaysOfWeek {
		if n, ok := weekdayNames[strings.ToLower(d)]; ok {
			days = append(days, n)
		}
	}
	var s string
	switch p.Type {
	case "daily":
		s = unit("day", "days")
	case "weekly":
		s = unit("week", "weeks")
		if len(days) > 0 {
			s += " on " + joinAnd(days)
		}
	case "absoluteMonthly":
		s = unit("month", "months")
		if p.DayOfMonth > 0 {
			s += fmt.Sprintf(" on day %d", p.DayOfMonth)
		}
	case "relativeMonthly":
		s = unit("month", "months")
		if len(days) > 0 {
			s += " on the " + p.Index + " " + joinAnd(days)
		}
	case "absoluteYearly":
		s = unit("year", "years")
		if p.Month >= 1 && p.Month <= 12 {
			s += " on " + time.Month(p.Month).String()
			if p.DayOfMonth > 0 {
				s += fmt.Sprintf(" %d", p.DayOfMonth)
			}
		}
	case "relativeYearly":
		s = unit("year", "years")
		if len(days) > 0 && p.Month >= 1 && p.Month <= 12 {
			s += " on the " + p.Index + " " + joinAnd(days) + " of " + time.Month(p.Month).String()
		}
	default:
		return "recurring"
	}
	switch r.Range.Type {
	case "endDate":
		if r.Range.EndDate != "" {
			s += ", until " + r.Range.EndDate
		}
	case "numbered":
		if r.Range.NumberOfOccurrences > 0 {
			s += fmt.Sprintf(", %d times", r.Range.NumberOfOccurrences)
		}
	}
	return s
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// ---------------------------------------------------------------- writing

const attendeesLead = "Proposed attendees: "

// composeDescription puts the attendees into the text, where the holder
// reads them, as the last paragraph. Never as attendees of the event:
// those are the people Graph would mail.
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

// newProposal is the event Graph is asked to create: tentative, asking
// nobody for a response, with no attendees, marked as the assistant's.
func newProposal(p cal.Proposal) map[string]any {
	attendees := cleanAttendees(p.Attendees)
	body := map[string]any{
		"subject":           strings.TrimSpace(p.Title),
		"start":             graphTime(p.Start),
		"end":               graphTime(p.End),
		"isAllDay":          p.AllDay,
		"showAs":            "tentative",
		"responseRequested": false,
		"singleValueExtendedProperties": []map[string]string{
			{"id": markerID, "value": marker{Ref: p.Ref, To: attendees}.encode()},
		},
	}
	if desc := composeDescription(p.Description, attendees); desc != "" {
		body["body"] = map[string]string{"contentType": "text", "content": desc}
	}
	if loc := strings.TrimSpace(p.Location); loc != "" {
		body["location"] = map[string]string{"displayName": loc}
	}
	return body
}

// patchOf is what changes on a proposed event. The status stays tentative
// and the mark stays: an update does not turn a proposal into a booking.
func patchOf(e event, m marker, p cal.Patch) map[string]any {
	body := map[string]any{"showAs": "tentative", "responseRequested": false}
	if p.Title != nil {
		body["subject"] = strings.TrimSpace(*p.Title)
	}
	if p.Location != nil {
		body["location"] = map[string]string{"displayName": strings.TrimSpace(*p.Location)}
	}
	if p.Start != nil || p.End != nil {
		start, end := parseGraphTime(e.Start.DateTime), parseGraphTime(e.End.DateTime)
		if p.Start != nil {
			start = *p.Start
		}
		if p.End != nil {
			end = *p.End
		}
		body["start"], body["end"] = graphTime(start), graphTime(end)
		// A time on an all-day event makes it a timed one, as the CalDAV
		// driver does.
		body["isAllDay"] = e.IsAllDay && p.Start == nil && p.End == nil
	}
	if p.Description != nil || p.Attendees != nil {
		base := ""
		if e.Body != nil {
			base = baseDescription(strings.TrimSpace(e.Body.Content))
		}
		if p.Description != nil {
			base = *p.Description
		}
		attendees := m.To
		if p.Attendees != nil {
			attendees = cleanAttendees(p.Attendees)
		}
		body["body"] = map[string]string{"contentType": "text", "content": composeDescription(base, attendees)}
		m.To = attendees
		body["singleValueExtendedProperties"] = []map[string]string{{"id": markerID, "value": m.encode()}}
	}
	return body
}
