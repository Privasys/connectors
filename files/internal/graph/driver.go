// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package graph

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Privasys/connectors/files/internal/cloud"
)

// How many sites and recent items are looked at when listing drives. The
// listing is what an agent reads to pick a drive; it is not an inventory.
const (
	maxSites  = 25
	maxRecent = 50
)

// Drives lists the holder's personal drive, then the document libraries of
// the SharePoint sites they follow, the sites the tenant lets them search,
// and any drive a recently used file lives in. A personal Microsoft account
// has no SharePoint and answers those legs with errors, which are ignored:
// the personal drive is the answer then, not a failure.
func (d *Driver) Drives(ctx context.Context) ([]cloud.Drive, error) {
	var me driveItemDrive
	if err := d.get(ctx, d.base+"/me/drive?$select=id,driveType,name,webUrl", &me); err != nil {
		return nil, err
	}
	name := "OneDrive"
	if me.DriveType == "business" {
		name = "OneDrive for work"
	}
	out := []cloud.Drive{{ID: me.ID, Name: name, Kind: "personal", WebURL: me.WebURL}}
	seen := map[string]bool{me.ID: true}
	add := func(dr cloud.Drive) {
		if dr.ID == "" || seen[dr.ID] {
			return
		}
		seen[dr.ID] = true
		out = append(out, dr)
	}

	type site struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Name        string `json:"name"`
	}
	sites := map[string]site{}
	var order []string
	for _, leg := range []string{
		d.base + "/me/followedSites?$select=id,displayName,name&$top=" + strconv.Itoa(maxSites),
		d.base + "/sites?search=*&$select=id,displayName,name&$top=" + strconv.Itoa(maxSites),
	} {
		var res struct {
			Value []site `json:"value"`
		}
		if err := d.get(ctx, leg, &res); err != nil {
			if errors.Is(err, cloud.ErrLogin) {
				return nil, err
			}
			continue
		}
		for _, s := range res.Value {
			if _, ok := sites[s.ID]; !ok && len(order) < maxSites {
				sites[s.ID] = s
				order = append(order, s.ID)
			}
		}
	}
	for _, id := range order {
		s := sites[id]
		var res struct {
			Value []driveItemDrive `json:"value"`
		}
		if err := d.get(ctx, d.base+"/sites/"+url.PathEscape(id)+"/drives?$select=id,driveType,name,webUrl", &res); err != nil {
			if errors.Is(err, cloud.ErrLogin) {
				return nil, err
			}
			continue
		}
		label := s.DisplayName
		if label == "" {
			label = s.Name
		}
		for _, dr := range res.Value {
			add(cloud.Drive{ID: dr.ID, Name: dr.Name, Kind: "sharepoint", Site: label, WebURL: dr.WebURL})
		}
	}

	// Recently used files name their drive in the resource reference, as
	// "drives/<id>/items/<id>". A drive not already listed is looked up.
	var used struct {
		Value []struct {
			ResourceReference struct {
				ID string `json:"id"`
			} `json:"resourceReference"`
		} `json:"value"`
	}
	if err := d.get(ctx, d.base+"/me/insights/used?$top="+strconv.Itoa(maxRecent), &used); err == nil {
		for _, u := range used.Value {
			m := driveRef.FindStringSubmatch(u.ResourceReference.ID)
			if m == nil || seen[m[1]] {
				continue
			}
			var dr driveItemDrive
			if err := d.get(ctx, d.base+"/drives/"+url.PathEscape(m[1])+"?$select=id,driveType,name,webUrl", &dr); err != nil {
				seen[m[1]] = true
				continue
			}
			kind := "sharepoint"
			if dr.DriveType == "personal" {
				kind = "personal"
			}
			add(cloud.Drive{ID: dr.ID, Name: dr.Name, Kind: kind, WebURL: dr.WebURL})
		}
	} else if errors.Is(err, cloud.ErrLogin) {
		return nil, err
	}
	return out, nil
}

var driveRef = regexp.MustCompile(`(?i)^/?drives/([^/]+)/items/`)

// List returns the children of a folder, newest first, one page at a time.
func (d *Driver) List(ctx context.Context, drive, folder string, limit int, pageToken string) ([]cloud.Item, string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if pageToken != "" {
		link, ok := decodePage(pageToken)
		if !ok || !d.ownURL(link) {
			return nil, "", errors.New("malformed page token")
		}
		return d.listPage(ctx, link, drive)
	}
	if drive == "" {
		drive = d.acct.DriveID
	}
	var target string
	folder = strings.TrimSpace(folder)
	switch {
	case folder == "" || folder == "/":
		target = d.base + "/drives/" + url.PathEscape(drive) + "/root/children"
	default:
		if idDrive, item, _, err := cloud.DecodeID(folder); err == nil {
			if idDrive != "" {
				drive = idDrive
			}
			target = d.base + "/drives/" + url.PathEscape(drive) + "/items/" + url.PathEscape(item) + "/children"
		} else {
			target = d.base + "/drives/" + url.PathEscape(drive) + "/root:/" + escapePath(folder) + ":/children"
		}
	}
	q := url.Values{"$top": {strconv.Itoa(limit)}, "$select": {itemSelect}, "$orderby": {"lastModifiedDateTime desc"}}
	items, next, err := d.listPage(ctx, target+"?"+q.Encode(), drive)
	if statusOf(err) == http.StatusBadRequest {
		// Not every library sorts on the server; then the page is sorted
		// here, which is the same order within the page.
		q.Del("$orderby")
		items, next, err = d.listPage(ctx, target+"?"+q.Encode(), drive)
		sort.SliceStable(items, func(i, j int) bool { return items[i].Modified.After(items[j].Modified) })
	}
	return items, next, err
}

func (d *Driver) listPage(ctx context.Context, link, drive string) ([]cloud.Item, string, error) {
	var p page
	if err := d.get(ctx, link, &p); err != nil {
		return nil, "", err
	}
	items := make([]cloud.Item, 0, len(p.Value))
	for _, it := range p.Value {
		items = append(items, d.item(it, drive))
	}
	next := ""
	if p.NextLink != "" {
		next = encodePage(p.NextLink)
	}
	return items, next, nil
}

// A page token is the provider's next link, encoded so it reads as a handle
// and is checked against the base before it is followed.
func encodePage(link string) string { return base64.RawURLEncoding.EncodeToString([]byte(link)) }

func decodePage(tok string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tok))
	if err != nil || len(raw) == 0 {
		return "", false
	}
	return string(raw), true
}

// Search runs Graph's search over one drive, or the personal drive.
func (d *Driver) Search(ctx context.Context, query, drive string, limit int) ([]cloud.Item, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("query is required")
	}
	if limit <= 0 || limit > 200 {
		limit = 25
	}
	if drive == "" {
		drive = d.acct.DriveID
	}
	q := url.Values{"$top": {strconv.Itoa(limit)}, "$select": {itemSelect}}
	target := d.base + "/drives/" + url.PathEscape(drive) + "/root/search(q='" + url.PathEscape(strings.ReplaceAll(query, "'", "''")) + "')?" + q.Encode()
	var p page
	if err := d.get(ctx, target, &p); err != nil {
		return nil, err
	}
	items := make([]cloud.Item, 0, len(p.Value))
	for _, it := range p.Value {
		if it.Deleted != nil {
			continue
		}
		items = append(items, d.item(it, drive))
	}
	return items, nil
}

// Fetch reads an item and, when it is a file no larger than max, its bytes.
// The content route answers with a redirect to a pre-authenticated URL on
// another host; that redirect is followed here by hand, without the bearer,
// rather than by the client, so the bearer cannot follow it anywhere.
func (d *Driver) Fetch(ctx context.Context, id string, max int64) (cloud.Content, error) {
	drive, itemID, etag, err := cloud.DecodeID(id)
	if err != nil {
		return cloud.Content{}, err
	}
	if drive == "" {
		drive = d.acct.DriveID
	}
	base := d.base + "/drives/" + url.PathEscape(drive) + "/items/" + url.PathEscape(itemID)
	var it driveItem
	if err := d.get(ctx, base+"?$select="+itemSelect, &it); err != nil {
		return cloud.Content{}, err
	}
	if etag != "" && it.ETag != "" && it.ETag != etag {
		return cloud.Content{}, cloud.ErrStale
	}
	out := cloud.Content{Item: d.item(it, drive)}
	if it.Folder != nil {
		return out, cloud.ErrIsFolder
	}
	if it.Size > max {
		return out, cloud.ErrTooLarge
	}
	res, err := d.download(ctx, base+"/content")
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil {
		return out, fmt.Errorf("graph: reading the content: %w", err)
	}
	if int64(len(data)) > max {
		return out, cloud.ErrTooLarge
	}
	out.Data = data
	out.MIME = res.Header.Get("Content-Type")
	if out.MIME == "" && it.File != nil {
		out.MIME = it.File.MimeType
	}
	return out, nil
}

// Save writes content as a new file under the connector's folder on the
// personal drive. The folder is created on first use, the subfolders under
// it likewise; a name already there gets a numbered suffix, and the upload
// itself is told to fail rather than replace, so a race with another writer
// ends in one more suffix and never in an overwrite.
func (d *Driver) Save(ctx context.Context, folder, name string, content []byte, mime string) (cloud.Item, error) {
	segs, err := cloud.CleanFolder(folder)
	if err != nil {
		return cloud.Item{}, err
	}
	name, _, err = cloud.CleanName(name)
	if err != nil {
		return cloud.Item{}, err
	}
	if int64(len(content)) > cloud.MaxSave {
		return cloud.Item{}, fmt.Errorf("the content is larger than %d bytes", cloud.MaxSave)
	}
	drive := d.acct.DriveID
	parent, err := d.ensureFolder(ctx, drive, append([]string{cloud.Folder}, segs...))
	if err != nil {
		return cloud.Item{}, err
	}
	taken, err := d.childNames(ctx, drive, parent)
	if err != nil {
		return cloud.Item{}, err
	}
	target := cloud.UniqueName(name, func(n string) bool { return taken[strings.ToLower(n)] })
	for attempt := 0; attempt < 5; attempt++ {
		var it driveItem
		err := d.do(ctx, http.MethodPut,
			d.base+"/drives/"+url.PathEscape(drive)+"/items/"+url.PathEscape(parent)+":/"+url.PathEscape(target)+":/content?@microsoft.graph.conflictBehavior=fail",
			bytes.NewReader(content), mime, &it)
		if err == nil {
			return d.item(it, drive), nil
		}
		if statusOf(err) != http.StatusConflict {
			return cloud.Item{}, err
		}
		// Someone wrote that name between the listing and the upload.
		taken[strings.ToLower(target)] = true
		target = cloud.UniqueName(name, func(n string) bool { return taken[strings.ToLower(n)] })
	}
	return cloud.Item{}, errors.New("could not find a free name after several attempts")
}

// ensureFolder walks the segments from the root, creating each folder that
// is missing, and returns the last one's id. Every path it can produce
// starts with the connector's folder, because the caller puts it first.
func (d *Driver) ensureFolder(ctx context.Context, drive string, segs []string) (string, error) {
	var parent string // "" is the root
	for _, seg := range segs {
		var it driveItem
		var lookup string
		if parent == "" {
			lookup = d.base + "/drives/" + url.PathEscape(drive) + "/root:/" + url.PathEscape(seg) + "?$select=id,name,folder"
		} else {
			lookup = d.base + "/drives/" + url.PathEscape(drive) + "/items/" + url.PathEscape(parent) + ":/" + url.PathEscape(seg) + "?$select=id,name,folder"
		}
		err := d.get(ctx, lookup, &it)
		switch {
		case err == nil:
			if it.Folder == nil {
				return "", fmt.Errorf("%q exists and is a file, not a folder", seg)
			}
			parent = it.ID
			continue
		case !errors.Is(err, cloud.ErrNotFound):
			return "", err
		}
		var create string
		if parent == "" {
			create = d.base + "/drives/" + url.PathEscape(drive) + "/root/children"
		} else {
			create = d.base + "/drives/" + url.PathEscape(drive) + "/items/" + url.PathEscape(parent) + "/children"
		}
		body := map[string]any{"name": seg, "folder": map[string]any{}, "@microsoft.graph.conflictBehavior": "fail"}
		if err := d.postJSON(ctx, create, body, &it); err != nil {
			if statusOf(err) == http.StatusConflict {
				// Created by someone else in the meantime: read it.
				if err := d.get(ctx, lookup, &it); err == nil && it.Folder != nil {
					parent = it.ID
					continue
				}
			}
			return "", err
		}
		parent = it.ID
	}
	return parent, nil
}

// childNames lists the names in a folder, lower-cased: OneDrive treats
// names case-insensitively, so the suffix rule must too.
func (d *Driver) childNames(ctx context.Context, drive, folderID string) (map[string]bool, error) {
	out := map[string]bool{}
	link := d.base + "/drives/" + url.PathEscape(drive) + "/items/" + url.PathEscape(folderID) + "/children?$select=id,name&$top=200"
	for pages := 0; link != "" && pages < 50; pages++ {
		var p page
		if err := d.get(ctx, link, &p); err != nil {
			return nil, err
		}
		for _, it := range p.Value {
			out[strings.ToLower(it.Name)] = true
		}
		link = p.NextLink
		if link != "" && !d.ownURL(link) {
			break
		}
	}
	return out, nil
}
