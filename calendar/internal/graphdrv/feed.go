// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package graphdrv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
	"github.com/Privasys/connectors/sdk/feed"
)

// The change feed is Graph's delta query on the default calendar's view:
// the first call pages through the window and ends on a delta link that
// stands for now; every later call follows the delta link, pages through
// what changed, and keeps the new delta link as the cursor. Graph pushes
// nothing to a client like this one, so inside the held call the link is
// followed every pollEvery until something comes back.
//
// A delta link is bound to the window it was minted for, so the cursor
// also carries when that was: a cursor older than reWindow is followed
// one last time and then minted afresh over a window that starts today.
// What that can miss is a change to an event more than sixty-two days
// ahead of the old cursor, made before the new one, which is the price of
// a query Graph will not run unbounded.
//
// The cursor is opaque to the harness, and an input when it comes back:
// the link is checked to still point at Graph before a bearer is sent to it.

// pollEvery is how often the held call asks Graph. A variable so a test can
// shorten it.
var pollEvery = 20 * time.Second

// The window a delta link covers: a week back, so an event moved into the
// past still reports, and the listing bound ahead.
const (
	windowBack = 7 * 24 * time.Hour
	reWindow   = 7 * 24 * time.Hour
)

type cursor struct {
	V    int    `json:"v"`
	Link string `json:"l"`
	// From is when the window was minted, Unix seconds.
	From int64 `json:"f"`
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (d *Driver) decodeCursor(s string) (cursor, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, false
	}
	var c cursor
	if err := json.Unmarshal(raw, &c); err != nil || c.V != 1 || c.Link == "" || !d.ownURL(c.Link) {
		return cursor{}, false
	}
	return c, true
}

// Changes reports what changed since the cursor, holding for up to wait
// when nothing has. No usable cursor (first call, or one from an earlier
// release) means "from now".
func (d *Driver) Changes(ctx context.Context, since string, wait time.Duration) ([]cal.Change, string, error) {
	state, ok := d.decodeCursor(since)
	if !ok {
		fresh, err := d.baseline(ctx)
		if err != nil {
			return nil, since, err
		}
		state = fresh
		if wait <= 0 {
			return nil, encodeCursor(state), nil
		}
	}
	var changes []cal.Change
	_, err := feed.Poll(ctx, wait, pollEvery, func(ctx context.Context) (bool, error) {
		found, err := d.look(ctx, &state)
		if err != nil {
			return false, err
		}
		changes = append(changes, found...)
		return len(changes) > 0, nil
	})
	if err != nil {
		return nil, since, err
	}
	return changes, encodeCursor(state), nil
}

// baseline runs the delta query to its end and keeps the link that stands
// for now.
func (d *Driver) baseline(ctx context.Context) (cursor, error) {
	now := d.now()
	q := url.Values{}
	q.Set("startDateTime", now.Add(-windowBack).UTC().Format(time.RFC3339))
	q.Set("endDateTime", now.Add(cal.MaxWindow).UTC().Format(time.RFC3339))
	link := d.base + "/me/calendarView/delta?" + q.Encode()
	for pages := 0; pages < maxPages*5; pages++ {
		var p page
		if err := d.get(ctx, link, &p); err != nil {
			return cursor{}, err
		}
		if p.DeltaLink != "" {
			if !d.ownURL(p.DeltaLink) {
				return cursor{}, errors.New("graph: the delta link points away from Graph")
			}
			return cursor{V: 1, Link: p.DeltaLink, From: now.Unix()}, nil
		}
		if p.NextLink == "" || !d.ownURL(p.NextLink) {
			break
		}
		link = p.NextLink
	}
	return cursor{}, errors.New("graph: the delta query handed back no delta link")
}

// look follows the delta link through its pages, moves the cursor on, and
// re-windows a cursor that has grown old. A link Graph no longer honours
// (410) can only say that the calendar changed; the cursor starts afresh.
func (d *Driver) look(ctx context.Context, state *cursor) ([]cal.Change, error) {
	var out []cal.Change
	seen := map[string]bool{}
	link := state.Link
	for pages := 0; pages < maxPages*5; pages++ {
		var p page
		if err := d.get(ctx, link, &p); err != nil {
			if statusOf(err) == http.StatusGone {
				fresh, berr := d.baseline(ctx)
				if berr != nil {
					return nil, berr
				}
				*state = fresh
				return []cal.Change{{Kind: "calendar_changed", Calendar: d.primary}}, nil
			}
			return nil, err
		}
		for _, e := range p.Value {
			if e.ID == "" || seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			ch := cal.Change{Kind: "changed", Calendar: d.primary, ID: eventRef{cal: d.primary, id: e.ID, changeKey: e.ChangeKey}.encode()}
			if e.Removed != nil {
				ch.Kind = "removed"
			}
			out = append(out, ch)
		}
		if p.DeltaLink != "" {
			if !d.ownURL(p.DeltaLink) {
				return nil, errors.New("graph: the delta link points away from Graph")
			}
			state.Link = p.DeltaLink
			break
		}
		if p.NextLink == "" || !d.ownURL(p.NextLink) {
			return nil, errors.New("graph: the delta page named neither a next nor a delta link")
		}
		link = p.NextLink
	}
	if d.now().Sub(time.Unix(state.From, 0)) > reWindow {
		fresh, err := d.baseline(ctx)
		if err != nil {
			return nil, err
		}
		*state = fresh
	}
	return out, nil
}
