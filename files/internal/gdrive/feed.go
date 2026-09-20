// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package gdrive

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Privasys/connectors/files/internal/cloud"
	"github.com/Privasys/connectors/sdk/feed"
)

// The change feed is Drive's changes.list: a start page token stands for
// now, and every later call lists the changes since the token it was handed
// and keeps the new start token as the cursor. Shared drives are included.
// Drive pushes nothing to a client like this one, so inside the held call
// the list is asked every pollEvery until something comes back.
//
// The cursor is the page token itself: Drive's, opaque, and only ever sent
// back to Drive as a query parameter, so there is nothing to check before
// following it.

// pollEvery is how often the held call asks Drive. A variable so a test can
// shorten it.
var pollEvery = 20 * time.Second

// Changes reports what changed since the cursor, holding for up to wait
// when nothing has. No cursor means "from now".
func (d *Driver) Changes(ctx context.Context, since string, wait time.Duration) ([]cloud.Change, string, error) {
	token := strings.TrimSpace(since)
	if token == "" {
		fresh, err := d.baseline(ctx)
		if err != nil {
			return nil, since, err
		}
		token = fresh
		if wait <= 0 {
			return nil, token, nil
		}
	}
	var changes []cloud.Change
	_, err := feed.Poll(ctx, wait, pollEvery, func(ctx context.Context) (bool, error) {
		found, next, err := d.look(ctx, token)
		if err != nil {
			return false, err
		}
		token = next
		changes = append(changes, found...)
		return len(changes) > 0, nil
	})
	if err != nil {
		return nil, since, err
	}
	return changes, token, nil
}

func (d *Driver) baseline(ctx context.Context) (string, error) {
	var res struct {
		StartPageToken string `json:"startPageToken"`
	}
	if err := d.get(ctx, d.base+"/changes/startPageToken?supportsAllDrives=true", &res); err != nil {
		return "", err
	}
	if res.StartPageToken == "" {
		return "", errors.New("drive: no start page token")
	}
	return res.StartPageToken, nil
}

// look pages through the changes since the token and returns them with the
// token to continue from. A token Drive no longer honours (400 or 404, the
// token has expired or is not one) is a reset and a fresh token.
func (d *Driver) look(ctx context.Context, token string) ([]cloud.Change, string, error) {
	var out []cloud.Change
	seen := map[string]bool{}
	for pages := 0; pages < 50; pages++ {
		q := url.Values{
			"pageToken": {token}, "pageSize": {"100"},
			"supportsAllDrives": {"true"}, "includeItemsFromAllDrives": {"true"},
			"fields": {"nextPageToken,newStartPageToken,changes(changeType,fileId,removed,file(" + fileFields + "))"},
		}
		var res struct {
			NextPageToken     string `json:"nextPageToken"`
			NewStartPageToken string `json:"newStartPageToken"`
			Changes           []struct {
				ChangeType string `json:"changeType"`
				FileID     string `json:"fileId"`
				Removed    bool   `json:"removed"`
				File       *file  `json:"file"`
			} `json:"changes"`
		}
		if err := d.get(ctx, d.base+"/changes?"+q.Encode(), &res); err != nil {
			if s := statusOf(err); s == http.StatusBadRequest || errors.Is(err, cloud.ErrNotFound) {
				fresh, berr := d.baseline(ctx)
				if berr != nil {
					return nil, token, berr
				}
				return []cloud.Change{{Kind: "reset"}}, fresh, nil
			}
			return nil, token, err
		}
		for _, c := range res.Changes {
			if c.ChangeType == "drive" || c.FileID == "" || seen[c.FileID] {
				continue
			}
			seen[c.FileID] = true
			ch := cloud.Change{Kind: "changed"}
			if c.Removed || (c.File != nil && c.File.Trashed) {
				ch.Kind = "removed"
			}
			drive, version := MyDrive, ""
			if c.File != nil {
				ch.Name = c.File.Name
				ch.Folder = c.File.MimeType == mimeFolder
				version = c.File.Version
				if c.File.DriveID != "" {
					drive = c.File.DriveID
				}
			}
			ch.ID = cloud.EncodeID(drive, c.FileID, version)
			out = append(out, ch)
		}
		if res.NewStartPageToken != "" {
			return out, res.NewStartPageToken, nil
		}
		if res.NextPageToken == "" {
			return out, token, errors.New("drive: a changes page named neither a next nor a new start token")
		}
		token = res.NextPageToken
	}
	return out, token, errors.New("drive: too many change pages in one look")
}
