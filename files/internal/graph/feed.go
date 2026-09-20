// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package graph

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/connectors/files/internal/cloud"
	"github.com/Privasys/connectors/sdk/feed"
)

// The change feed is Graph's delta query on the personal drive's root:
// the first call asks for "latest", which is an empty page and a delta
// link that stands for now; every later call follows the delta link,
// pages through what changed, and keeps the new delta link as the cursor.
// Graph pushes nothing to a client like this one, so inside the held call
// the link is followed every pollEvery until something comes back.
//
// The cursor is the delta link, encoded so it reads as a handle. It is an
// input when it comes back, so it is checked to still point at Graph before
// a bearer is sent to it.

// pollEvery is how often the held call asks Graph. A variable so a test can
// shorten it.
var pollEvery = 20 * time.Second

func encodeCursor(link string) string { return base64.RawURLEncoding.EncodeToString([]byte(link)) }

func (d *Driver) decodeCursor(s string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) == 0 || !d.ownURL(string(raw)) {
		return "", false
	}
	return string(raw), true
}

// Changes reports what changed since the cursor, holding for up to wait
// when nothing has. No usable cursor means "from now".
func (d *Driver) Changes(ctx context.Context, since string, wait time.Duration) ([]cloud.Change, string, error) {
	link, ok := d.decodeCursor(since)
	if !ok {
		fresh, err := d.baseline(ctx)
		if err != nil {
			return nil, since, err
		}
		link = fresh
		if wait <= 0 {
			return nil, encodeCursor(link), nil
		}
	}
	var changes []cloud.Change
	_, err := feed.Poll(ctx, wait, pollEvery, func(ctx context.Context) (bool, error) {
		found, next, err := d.look(ctx, link)
		if err != nil {
			return false, err
		}
		link = next
		changes = append(changes, found...)
		return len(changes) > 0, nil
	})
	if err != nil {
		return nil, since, err
	}
	return changes, encodeCursor(link), nil
}

// baseline asks for the delta link that stands for now.
func (d *Driver) baseline(ctx context.Context) (string, error) {
	link := d.base + "/drives/" + d.acct.DriveID + "/root/delta?token=latest"
	for pages := 0; pages < 20; pages++ {
		var p page
		if err := d.get(ctx, link, &p); err != nil {
			return "", err
		}
		if p.DeltaLink != "" {
			return p.DeltaLink, nil
		}
		if p.NextLink == "" || !d.ownURL(p.NextLink) {
			break
		}
		link = p.NextLink
	}
	return "", errors.New("graph: the delta query handed back no delta link")
}

// look follows the delta link through its pages and returns what changed
// and the link to continue from. A link Graph no longer honours (410,
// resyncRequired) is reported as a reset and replaced with a fresh one.
func (d *Driver) look(ctx context.Context, link string) ([]cloud.Change, string, error) {
	var out []cloud.Change
	seen := map[string]bool{}
	for pages := 0; pages < 50; pages++ {
		var p page
		if err := d.get(ctx, link, &p); err != nil {
			if statusOf(err) == http.StatusGone {
				fresh, berr := d.baseline(ctx)
				if berr != nil {
					return nil, link, berr
				}
				return []cloud.Change{{Kind: "reset"}}, fresh, nil
			}
			return nil, link, err
		}
		for _, it := range p.Value {
			if it.Root != nil || it.ID == "" || seen[it.ID] {
				continue
			}
			seen[it.ID] = true
			ch := cloud.Change{Kind: "changed", Name: it.Name, Folder: it.Folder != nil}
			if it.Deleted != nil {
				ch.Kind = "removed"
			}
			ch.ID = cloud.EncodeID(d.acct.DriveID, it.ID, it.ETag)
			out = append(out, ch)
		}
		if p.DeltaLink != "" {
			return out, p.DeltaLink, nil
		}
		if p.NextLink == "" || !d.ownURL(p.NextLink) {
			return out, link, errors.New("graph: the delta page named neither a next nor a delta link")
		}
		link = p.NextLink
	}
	return out, link, errors.New("graph: too many delta pages in one look")
}
