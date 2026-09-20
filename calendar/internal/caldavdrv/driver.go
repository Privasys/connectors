// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package caldavdrv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav/caldav"
)

// everything asks the server for whole objects: every property and every
// component, because the expansion of a recurring event needs the rule, the
// exceptions and the overrides together.
var everything = caldav.CalendarCompRequest{Name: ical.CompCalendar, AllProps: true, AllComps: true}

// Calendars lists the holder's calendars, which one is primary.
func (d *Driver) Calendars(ctx context.Context) ([]cal.Calendar, error) {
	out := make([]cal.Calendar, 0, len(d.cals))
	for _, c := range d.cals {
		out = append(out, cal.Calendar{
			ID: calendarID(c.path), Name: c.name, Description: c.desc, Primary: c.primary, ReadOnly: c.readOnly,
		})
	}
	return out, nil
}

// find returns the calendar for an id, or the primary for "".
func (d *Driver) find(id string) (calendar, error) {
	if strings.TrimSpace(id) == "" {
		for _, c := range d.cals {
			if c.primary {
				return c, nil
			}
		}
		return calendar{}, errors.New("no primary calendar")
	}
	p, err := calendarPath(id)
	if err != nil {
		return calendar{}, err
	}
	for _, c := range d.cals {
		if c.path == p {
			return c, nil
		}
	}
	return calendar{}, fmt.Errorf("no such calendar for this account")
}

// Events returns the occurrences in [from, to), soonest first: a time-range
// query per calendar, then the expansion of what came back. Never a full
// scan, and never a window longer than cal.MaxWindow.
func (d *Driver) Events(ctx context.Context, calendarID string, from, to time.Time) ([]cal.Event, error) {
	if !to.After(from) {
		return nil, errors.New("the window is empty: to must be after from")
	}
	if to.Sub(from) > cal.MaxWindow {
		return nil, fmt.Errorf("the window is longer than %d days; ask for less", int(cal.MaxWindow.Hours()/24))
	}
	var cals []calendar
	if strings.TrimSpace(calendarID) == "" {
		cals = d.cals
	} else {
		c, err := d.find(calendarID)
		if err != nil {
			return nil, err
		}
		cals = []calendar{c}
	}
	var out []cal.Event
	for _, c := range cals {
		objs, err := d.query(ctx, c.path, from, to)
		if err != nil {
			return nil, fmt.Errorf("calendar %q: %w", c.name, err)
		}
		for _, o := range objs {
			out = append(out, occurrences(o, from, to, d.cfg.User)...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out, nil
}

// query is one time-range REPORT.
func (d *Driver) query(ctx context.Context, calPath string, from, to time.Time) ([]object, error) {
	objs, err := d.dav.QueryCalendar(ctx, calPath, &caldav.CalendarQuery{
		CompRequest: everything,
		CompFilter: caldav.CompFilter{
			Name:  ical.CompCalendar,
			Comps: []caldav.CompFilter{{Name: ical.CompEvent, Start: from.UTC(), End: to.UTC()}},
		},
	})
	if err != nil {
		return nil, describe(err)
	}
	out := make([]object, 0, len(objs))
	for _, o := range objs {
		if o.Data == nil {
			continue
		}
		out = append(out, object{cal: calPath, href: o.Path, etag: o.ETag, data: o.Data})
	}
	return out, nil
}

// fetch reads one object by its id and checks it is the version the id was
// minted for.
func (d *Driver) fetch(ctx context.Context, id string) (eventRef, object, error) {
	ref, err := parseID(id)
	if err != nil {
		return ref, object{}, err
	}
	co, err := d.dav.GetCalendarObject(ctx, ref.href)
	if err != nil {
		if statusOf(err) == http.StatusNotFound {
			return ref, object{}, cal.ErrNotFound
		}
		return ref, object{}, describe(err)
	}
	if ref.etag != "" && co.ETag != "" && co.ETag != ref.etag {
		return ref, object{}, cal.ErrStale
	}
	return ref, object{cal: ref.cal, href: co.Path, etag: co.ETag, data: co.Data}, nil
}

// Get returns one event in full: the one-off, or the one occurrence the id
// names.
func (d *Driver) Get(ctx context.Context, id string) (cal.Event, error) {
	ref, o, err := d.fetch(ctx, id)
	if err != nil {
		return cal.Event{}, err
	}
	return pick(ref, o, d.cfg.User)
}

// pick is the occurrence an id names out of an object.
func pick(ref eventRef, o object, self string) (cal.Event, error) {
	if ref.instance == "" {
		if ev, ok := single(o, self); ok {
			return ev, nil
		}
		return cal.Event{}, cal.ErrNotFound
	}
	at, err := time.Parse(time.RFC3339, ref.instance)
	if err != nil {
		return cal.Event{}, cal.ErrBadID
	}
	// A window around the occurrence: the rule produces it, or the override
	// that replaced it does, whichever is in the object.
	for _, ev := range occurrences(o, at.Add(-48*time.Hour), at.Add(48*time.Hour), self) {
		if r, err := parseID(ev.ID); err == nil && r.instance == ref.instance {
			return ev, nil
		}
	}
	return cal.Event{}, cal.ErrNotFound
}

// single is the object as one event: its master VEVENT with its own span, no
// expansion. What an id with no instance names, and what a write is reread as.
func single(o object, self string) (cal.Event, bool) {
	if o.data == nil {
		return cal.Event{}, false
	}
	for _, e := range o.data.Events() {
		if e.Props.Get(ical.PropRecurrenceID) != nil {
			continue
		}
		if start, end, allDay, ok := span(&e); ok {
			return eventFrom(e, o, start, end, allDay, "", self), true
		}
	}
	return cal.Event{}, false
}

// Propose creates a TENTATIVE event, marked as the assistant's, with no
// attendees on it: the people it is for are named in the text, and no
// server sends anyone anything.
func (d *Driver) Propose(ctx context.Context, calendarID string, p cal.Proposal) (cal.Event, error) {
	c, err := d.find(calendarID)
	if err != nil {
		return cal.Event{}, err
	}
	if c.readOnly {
		return cal.Event{}, errors.New("that calendar is read-only for this account")
	}
	if strings.TrimSpace(p.Title) == "" {
		return cal.Event{}, errors.New("title is required")
	}
	if !p.End.After(p.Start) {
		return cal.Event{}, errors.New("end must be after start")
	}
	if strings.TrimSpace(p.Ref) == "" {
		p.Ref = newUID()
	}
	obj, uid := newProposal(p, d.now())
	href := path.Join(c.path, uid+".ics")
	// If-None-Match: * so that a collision on the uid, which cannot happen
	// but must not overwrite if it did, fails.
	pctx := withHeaders(ctx, http.Header{"If-None-Match": {"*"}})
	if _, err := d.dav.PutCalendarObject(pctx, href, obj); err != nil {
		return cal.Event{}, describe(err)
	}
	return d.reread(ctx, c.path, href)
}

// reread fetches an object after a write, for the etag the server gave it
// (a PUT does not always answer with one) and the event as it now stands.
func (d *Driver) reread(ctx context.Context, calPath, href string) (cal.Event, error) {
	co, err := d.dav.GetCalendarObject(ctx, href)
	if err != nil {
		return cal.Event{}, describe(err)
	}
	ev, ok := single(object{cal: calPath, href: co.Path, etag: co.ETag, data: co.Data}, d.cfg.User)
	if !ok {
		return cal.Event{}, errors.New("the server stored the event but does not return it")
	}
	return ev, nil
}

// proposed fetches an id and refuses it unless it is the assistant's own.
func (d *Driver) proposed(ctx context.Context, id string) (eventRef, object, *ical.Event, error) {
	ref, o, err := d.fetch(ctx, id)
	if err != nil {
		return ref, o, nil, err
	}
	for _, e := range o.data.Events() {
		e := e
		if p := e.Props.Get(cal.ProposedProp); p != nil && e.Props.Get(ical.PropRecurrenceID) == nil {
			return ref, o, &e, nil
		}
	}
	return ref, o, nil, cal.ErrNotProposed
}

// Update changes a proposed event and nothing else. The write carries the
// etag the id was read at, so two agents editing the same proposal cannot
// silently overwrite each other.
func (d *Driver) Update(ctx context.Context, id string, p cal.Patch) (cal.Event, error) {
	ref, o, ev, err := d.proposed(ctx, id)
	if err != nil {
		return cal.Event{}, err
	}
	if p.Start != nil || p.End != nil {
		start, end, _, _ := span(ev)
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
	if p.Title != nil && strings.TrimSpace(*p.Title) == "" {
		return cal.Event{}, errors.New("title cannot be empty")
	}
	applyPatch(ev, p, d.now())
	pctx := ctx
	if o.etag != "" {
		pctx = withHeaders(ctx, http.Header{"If-Match": {`"` + o.etag + `"`}})
	}
	if _, err := d.dav.PutCalendarObject(pctx, o.href, o.data); err != nil {
		if statusOf(err) == http.StatusPreconditionFailed {
			return cal.Event{}, cal.ErrStale
		}
		return cal.Event{}, describe(err)
	}
	return d.reread(ctx, ref.cal, o.href)
}

// Delete removes a proposed event and nothing else.
func (d *Driver) Delete(ctx context.Context, id string) error {
	_, o, _, err := d.proposed(ctx, id)
	if err != nil {
		return err
	}
	dctx := ctx
	if o.etag != "" {
		dctx = withHeaders(ctx, http.Header{"If-Match": {`"` + o.etag + `"`}})
	}
	if err := d.dav.RemoveAll(dctx, o.href); err != nil {
		switch statusOf(err) {
		case http.StatusPreconditionFailed:
			return cal.ErrStale
		case http.StatusNotFound:
			return cal.ErrNotFound
		}
		return describe(err)
	}
	return nil
}

// describe turns a sign-in refusal into ErrLogin and leaves the rest as the
// server said it.
func describe(err error) error {
	switch statusOf(err) {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w (%v)", ErrLogin, err)
	}
	return err
}
