// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package caldavdrv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
	"github.com/Privasys/connectors/sdk/feed"
	"github.com/emersion/go-webdav/caldav"
)

// The change feed. A CalDAV server pushes nothing, so inside the held call
// the driver asks every calendar for its sync token (RFC 6578) and its ctag
// every pollEvery, and reports when either moved. With a sync token the
// changes are the exact objects, through a sync-collection REPORT; with a
// ctag alone the server can only say that the calendar changed, and the
// feed says that, so the agent lists again.
//
// The cursor is the tokens, per calendar, encoded. Opaque: the harness hands
// it back and never reads into it.

// pollEvery is how often the held call asks the server. A variable so a test
// can shorten it.
var pollEvery = 20 * time.Second

// cursor is what the feed compares against.
type cursor struct {
	V         int                  `json:"v"`
	Calendars map[string]calCursor `json:"c"`
}

type calCursor struct {
	Token string `json:"t,omitempty"`
	CTag  string `json:"g,omitempty"`
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, false
	}
	var c cursor
	if err := json.Unmarshal(raw, &c); err != nil || c.V != 1 || c.Calendars == nil {
		return cursor{}, false
	}
	return c, true
}

// Changes reports what changed since the cursor, holding for up to wait
// when nothing has. No usable cursor (first call, or one from an earlier
// release) means "from now": nothing is reported as having changed, and the
// cursor handed back is a real one.
func (d *Driver) Changes(ctx context.Context, since string, wait time.Duration) ([]cal.Change, string, error) {
	state, ok := decodeCursor(since)
	if !ok {
		state = cursor{V: 1, Calendars: map[string]calCursor{}}
		if err := d.baseline(ctx, &state); err != nil {
			return nil, since, err
		}
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

// baseline records where every calendar is now.
func (d *Driver) baseline(ctx context.Context, state *cursor) error {
	for _, c := range d.cals {
		ctag, token, err := d.t.syncState(ctx, d.calendarURL(c.path))
		if err != nil {
			return describe(err)
		}
		state.Calendars[c.path] = calCursor{Token: token, CTag: ctag}
	}
	return nil
}

// look compares every calendar with the cursor and moves the cursor on.
func (d *Driver) look(ctx context.Context, state *cursor) ([]cal.Change, error) {
	var out []cal.Change
	seen := map[string]bool{}
	for _, c := range d.cals {
		seen[c.path] = true
		ctag, token, err := d.t.syncState(ctx, d.calendarURL(c.path))
		if err != nil {
			return nil, describe(err)
		}
		prev, known := state.Calendars[c.path]
		id := calendarID(c.path)
		switch {
		case !known:
			// A calendar that appeared since the cursor was minted.
			out = append(out, cal.Change{Kind: "calendar_changed", Calendar: id})
		case prev.Token != "" && token != "":
			if token == prev.Token {
				state.Calendars[c.path] = calCursor{Token: token, CTag: ctag}
				continue
			}
			found, newToken, err := d.sync(ctx, c.path, prev.Token)
			if err != nil {
				if statusOf(err) == http.StatusUnauthorized || statusOf(err) == http.StatusForbidden {
					return nil, describe(err)
				}
				// A token the server no longer honours: say the calendar
				// changed and start again from its now.
				out = append(out, cal.Change{Kind: "calendar_changed", Calendar: id})
				break
			}
			out = append(out, found...)
			token = newToken
		default:
			// No sync token on one side or the other: the ctag is the word,
			// and a server with neither cannot be watched at all.
			same := true
			switch {
			case ctag != "" || prev.CTag != "":
				same = ctag == prev.CTag
			case token != "" || prev.Token != "":
				same = token == prev.Token
			}
			if same {
				state.Calendars[c.path] = calCursor{Token: token, CTag: ctag}
				continue
			}
			out = append(out, cal.Change{Kind: "calendar_changed", Calendar: id})
		}
		state.Calendars[c.path] = calCursor{Token: token, CTag: ctag}
	}
	for p := range state.Calendars {
		if !seen[p] {
			delete(state.Calendars, p)
			out = append(out, cal.Change{Kind: "calendar_changed", Calendar: calendarID(p)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Kind+out[i].ID < out[j].Kind+out[j].ID })
	return out, nil
}

// sync is one sync-collection REPORT: the objects that changed or went since
// the token, and the token to continue from.
func (d *Driver) sync(ctx context.Context, calPath, token string) ([]cal.Change, string, error) {
	res, err := d.dav.SyncCollection(ctx, calPath, &caldav.SyncQuery{CompRequest: everything, SyncToken: token})
	if err != nil {
		return nil, "", describe(err)
	}
	var out []cal.Change
	for _, o := range res.Updated {
		out = append(out, cal.Change{
			ID: eventRef{cal: calPath, href: o.Path, etag: o.ETag}.id(), Kind: "changed", Calendar: calendarID(calPath),
		})
	}
	for _, p := range res.Deleted {
		out = append(out, cal.Change{
			ID: eventRef{cal: calPath, href: p}.id(), Kind: "removed", Calendar: calendarID(calPath),
		})
	}
	return out, res.SyncToken, nil
}
