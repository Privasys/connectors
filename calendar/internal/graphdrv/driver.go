// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package graphdrv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
)

// Calendars lists the holder's calendars, the default one marked primary.
func (d *Driver) Calendars(ctx context.Context) ([]cal.Calendar, error) {
	var out []cal.Calendar
	next := d.base + "/me/calendars?$select=id,name,isDefaultCalendar,canEdit&$top=100"
	for pages := 0; next != "" && pages < maxPages; pages++ {
		var body struct {
			Value    []calendarItem `json:"value"`
			NextLink string         `json:"@odata.nextLink"`
		}
		if err := d.get(ctx, next, &body); err != nil {
			return nil, err
		}
		for _, c := range body.Value {
			out = append(out, cal.Calendar{ID: c.ID, Name: c.Name, Primary: c.IsDefaultCalendar, ReadOnly: !c.CanEdit})
			if c.IsDefaultCalendar {
				d.primary = c.ID
			}
		}
		if body.NextLink != "" && !d.ownURL(body.NextLink) {
			return nil, errors.New("graph: the next link points away from Graph")
		}
		next = body.NextLink
	}
	if d.primary == "" && len(out) > 0 {
		d.primary = out[0].ID
	}
	return out, nil
}

// Events returns the occurrences in [from, to) on one calendar, or on all
// when calendar is empty, soonest first. The calendar view expands a
// recurring event into its occurrences; the sentence about the rule comes
// from the series master, read once per series.
func (d *Driver) Events(ctx context.Context, calendar string, from, to time.Time) ([]cal.Event, error) {
	if !to.After(from) {
		return nil, errors.New("to must be after from")
	}
	if to.Sub(from) > cal.MaxWindow {
		return nil, fmt.Errorf("the window is longer than %d days", int(cal.MaxWindow.Hours()/24))
	}
	var ids []string
	if calendar != "" {
		ids = []string{calendar}
	} else {
		cals, err := d.Calendars(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range cals {
			ids = append(ids, c.ID)
		}
	}
	rules := map[string]string{}
	var out []cal.Event
	for _, id := range ids {
		evs, err := d.view(ctx, id, from, to, rules)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out, nil
}

// view is one calendar's view of the window.
func (d *Driver) view(ctx context.Context, calendar string, from, to time.Time, rules map[string]string) ([]cal.Event, error) {
	q := url.Values{}
	q.Set("startDateTime", from.UTC().Format(time.RFC3339))
	q.Set("endDateTime", to.UTC().Format(time.RFC3339))
	q.Set("$select", eventSelect)
	q.Set("$expand", eventExpand)
	q.Set("$orderby", "start/dateTime")
	q.Set("$top", "100")
	next := d.base + "/me/calendars/" + url.PathEscape(calendar) + "/calendarView?" + q.Encode()
	var out []cal.Event
	for pages := 0; next != "" && pages < maxPages; pages++ {
		var p page
		if err := d.get(ctx, next, &p); err != nil {
			return nil, err
		}
		for _, e := range p.Value {
			ev := convert(e, calendar, d.user)
			if ev.Recurrence == "" && e.SeriesMasterID != "" {
				ev.Recurrence = d.rule(ctx, e.SeriesMasterID, rules)
			}
			out = append(out, ev)
		}
		if p.NextLink != "" && !d.ownURL(p.NextLink) {
			return nil, errors.New("graph: the next link points away from Graph")
		}
		next = p.NextLink
	}
	return out, nil
}

// rule reads a series master's recurrence, once per listing. A master
// that cannot be read leaves the occurrence saying only that it recurs.
func (d *Driver) rule(ctx context.Context, masterID string, rules map[string]string) string {
	if s, ok := rules[masterID]; ok {
		return s
	}
	var master struct {
		Recurrence *recurrence `json:"recurrence"`
	}
	s := "recurring"
	if err := d.get(ctx, d.base+"/me/events/"+url.PathEscape(masterID)+"?$select=recurrence", &master); err == nil && master.Recurrence != nil {
		s = recurrenceText(*master.Recurrence)
	}
	rules[masterID] = s
	return s
}

// fetch reads one event by Graph id, with the mark expanded.
func (d *Driver) fetch(ctx context.Context, id string) (event, error) {
	var e event
	err := d.get(ctx, d.base+"/me/events/"+url.PathEscape(id)+"?$select="+eventSelect+"&$expand="+url.QueryEscape(eventExpand), &e)
	return e, err
}

// Get reads one event by an id from a listing. An id whose changeKey is no
// longer the event's is stale.
func (d *Driver) Get(ctx context.Context, id string) (cal.Event, error) {
	ref, err := parseID(id)
	if err != nil {
		return cal.Event{}, err
	}
	e, err := d.fetch(ctx, ref.id)
	if err != nil {
		return cal.Event{}, err
	}
	if ref.changeKey != "" && e.ChangeKey != "" && e.ChangeKey != ref.changeKey {
		return cal.Event{}, cal.ErrStale
	}
	ev := convert(e, ref.cal, d.user)
	if ev.Recurrence == "" && e.SeriesMasterID != "" {
		ev.Recurrence = d.rule(ctx, e.SeriesMasterID, map[string]string{})
	}
	return ev, nil
}

// Propose creates a tentative event with no attendees on the calendar, or
// on the default one when calendar is empty, and reads it back for the
// changeKey Graph gave it.
func (d *Driver) Propose(ctx context.Context, calendar string, p cal.Proposal) (cal.Event, error) {
	if strings.TrimSpace(p.Title) == "" {
		return cal.Event{}, errors.New("title is required")
	}
	if !p.End.After(p.Start) {
		return cal.Event{}, errors.New("end must be after start")
	}
	if strings.TrimSpace(p.Ref) == "" {
		p.Ref = fmt.Sprintf("privasys-%d", d.now().UnixNano())
	}
	if calendar == "" {
		if d.primary == "" {
			if _, err := d.Calendars(ctx); err != nil {
				return cal.Event{}, err
			}
		}
		calendar = d.primary
	}
	if calendar == "" {
		return cal.Event{}, errors.New("the account has no calendar to propose on")
	}
	var created struct {
		ID string `json:"id"`
	}
	target := d.base + "/me/calendars/" + url.PathEscape(calendar) + "/events"
	if err := d.do(ctx, http.MethodPost, target, newProposal(p), &created); err != nil {
		return cal.Event{}, err
	}
	if created.ID == "" {
		return cal.Event{}, errors.New("graph stored the event but does not name it")
	}
	return d.Get(ctx, eventRef{cal: calendar, id: created.ID}.encode())
}

// proposed reads an event and refuses it unless it carries the mark and
// the id still names its current version.
func (d *Driver) proposed(ctx context.Context, id string) (eventRef, event, marker, error) {
	ref, err := parseID(id)
	if err != nil {
		return ref, event{}, marker{}, err
	}
	e, err := d.fetch(ctx, ref.id)
	if err != nil {
		return ref, event{}, marker{}, err
	}
	m, ok := e.mark()
	if !ok {
		return ref, event{}, marker{}, cal.ErrNotProposed
	}
	if ref.changeKey != "" && e.ChangeKey != "" && e.ChangeKey != ref.changeKey {
		return ref, event{}, marker{}, cal.ErrStale
	}
	return ref, e, m, nil
}

// Update changes a proposed event and nothing else.
func (d *Driver) Update(ctx context.Context, id string, p cal.Patch) (cal.Event, error) {
	ref, e, m, err := d.proposed(ctx, id)
	if err != nil {
		return cal.Event{}, err
	}
	if p.Start != nil || p.End != nil {
		start, end := parseGraphTime(e.Start.DateTime), parseGraphTime(e.End.DateTime)
		if p.Start != nil {
			start = *p.Start
		}
		if p.End != nil {
			end = *p.End
		}
		if !end.After(start) {
			return cal.Event{}, errors.New("end must be after start")
		}
	}
	if err := d.do(ctx, http.MethodPatch, d.base+"/me/events/"+url.PathEscape(ref.id), patchOf(e, m, p), nil); err != nil {
		return cal.Event{}, err
	}
	return d.Get(ctx, eventRef{cal: ref.cal, id: ref.id}.encode())
}

// Delete removes a proposed event and nothing else.
func (d *Driver) Delete(ctx context.Context, id string) error {
	ref, _, _, err := d.proposed(ctx, id)
	if err != nil {
		return err
	}
	return d.do(ctx, http.MethodDelete, d.base+"/me/events/"+url.PathEscape(ref.id), nil, nil)
}
