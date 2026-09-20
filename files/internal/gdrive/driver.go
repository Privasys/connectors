// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package gdrive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/Privasys/connectors/files/internal/cloud"
)

// Drives lists My Drive and the shared drives the holder can see.
func (d *Driver) Drives(ctx context.Context) ([]cloud.Drive, error) {
	out := []cloud.Drive{{ID: MyDrive, Name: "My Drive", Kind: "personal", WebURL: "https://drive.google.com/drive/my-drive"}}
	var res struct {
		Drives []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"drives"`
	}
	if err := d.get(ctx, d.base+"/drives?pageSize=100&fields=drives(id,name)", &res); err != nil {
		// A consumer account has no shared drives and may answer this
		// with an error rather than an empty list; My Drive is still the
		// answer then.
		if errors.Is(err, cloud.ErrLogin) {
			return nil, err
		}
		return out, nil
	}
	for _, dr := range res.Drives {
		out = append(out, cloud.Drive{ID: dr.ID, Name: dr.Name, Kind: "shared", WebURL: "https://drive.google.com/drive/folders/" + url.PathEscape(dr.ID)})
	}
	return out, nil
}

// List returns the children of a folder, newest first. The folder is a
// path from the drive's root, resolved a segment at a time by name, an id
// from a listing, or "" for the root; the root of a shared drive is the
// drive itself.
func (d *Driver) List(ctx context.Context, drive, folder string, limit int, pageToken string) ([]cloud.Item, string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if drive == "" {
		drive = MyDrive
	}
	parent, err := d.resolve(ctx, drive, folder)
	if err != nil {
		return nil, "", err
	}
	q := url.Values{
		"q":        {quote(parent) + " in parents and trashed = false"},
		"orderBy":  {"modifiedTime desc"},
		"pageSize": {strconv.Itoa(limit)},
	}
	if pageToken != "" {
		q.Set("pageToken", pageToken)
	}
	d.scope(q, drive)
	var res fileList
	if err := d.get(ctx, d.listQuery(q), &res); err != nil {
		return nil, "", err
	}
	items := make([]cloud.Item, 0, len(res.Files))
	for _, f := range res.Files {
		items = append(items, d.item(f))
	}
	return items, res.NextPageToken, nil
}

// scope narrows a listing to one shared drive, or leaves it at the
// holder's own files.
func (d *Driver) scope(q url.Values, drive string) {
	if drive != "" && drive != MyDrive {
		q.Set("corpora", "drive")
		q.Set("driveId", drive)
	}
}

// resolve turns a folder argument into a folder id.
func (d *Driver) resolve(ctx context.Context, drive, folder string) (string, error) {
	folder = strings.TrimSpace(folder)
	if folder == "" || folder == "/" {
		return drive, nil
	}
	if idDrive, id, _, err := cloud.DecodeID(folder); err == nil {
		_ = idDrive
		return id, nil
	}
	parent := drive
	for _, seg := range strings.Split(strings.Trim(folder, "/"), "/") {
		if seg == "" {
			continue
		}
		q := url.Values{
			"q":        {"name = " + quote(seg) + " and " + quote(parent) + " in parents and mimeType = " + quote(mimeFolder) + " and trashed = false"},
			"pageSize": {"1"},
		}
		d.scope(q, drive)
		var res fileList
		if err := d.get(ctx, d.listQuery(q), &res); err != nil {
			return "", err
		}
		if len(res.Files) == 0 {
			return "", fmt.Errorf("%w: no folder %q", cloud.ErrNotFound, seg)
		}
		parent = res.Files[0].ID
	}
	return parent, nil
}

// Search runs Drive's full-text search over one shared drive, or over
// everything the holder can see when drive is "" or My Drive.
func (d *Driver) Search(ctx context.Context, query, drive string, limit int) ([]cloud.Item, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("query is required")
	}
	if limit <= 0 || limit > 200 {
		limit = 25
	}
	q := url.Values{
		"q":        {"fullText contains " + quote(query) + " and trashed = false"},
		"pageSize": {strconv.Itoa(limit)},
	}
	if drive != "" && drive != MyDrive {
		d.scope(q, drive)
	} else {
		q.Set("corpora", "allDrives")
	}
	var res fileList
	if err := d.get(ctx, d.listQuery(q), &res); err != nil {
		return nil, err
	}
	items := make([]cloud.Item, 0, len(res.Files))
	for _, f := range res.Files {
		items = append(items, d.item(f))
	}
	return items, nil
}

// Fetch reads a file's metadata and its bytes: a download for an ordinary
// file, an export as text for a Google document, sheet or presentation.
func (d *Driver) Fetch(ctx context.Context, id string, max int64) (cloud.Content, error) {
	_, fileID, version, err := cloud.DecodeID(id)
	if err != nil {
		return cloud.Content{}, err
	}
	base := d.base + "/files/" + url.PathEscape(fileID)
	var f file
	if err := d.get(ctx, base+"?supportsAllDrives=true&fields="+url.QueryEscape(fileFields), &f); err != nil {
		return cloud.Content{}, err
	}
	if f.Trashed {
		return cloud.Content{}, cloud.ErrNotFound
	}
	if version != "" && f.Version != "" && f.Version != version {
		return cloud.Content{}, cloud.ErrStale
	}
	out := cloud.Content{Item: d.item(f)}
	if f.MimeType == mimeFolder {
		return out, cloud.ErrIsFolder
	}
	var target string
	switch f.MimeType {
	case mimeDocument, mimePresentation:
		target, out.MIME, out.Exported = base+"/export?mimeType=text/plain", "text/plain", true
	case mimeSpreadsheet:
		target, out.MIME, out.Exported = base+"/export?mimeType=text/csv", "text/csv", true
	default:
		if strings.HasPrefix(f.MimeType, "application/vnd.google-apps.") {
			// A form, a drawing, a shortcut, a map: nothing to read.
			return out, cloud.ErrNoText
		}
		if out.Item.Size > max {
			return out, cloud.ErrTooLarge
		}
		target, out.MIME = base+"?alt=media&supportsAllDrives=true", f.MimeType
	}
	res, err := d.send(ctx, http.MethodGet, target, nil, "")
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil {
		return out, fmt.Errorf("drive: reading the content: %w", err)
	}
	if int64(len(data)) > max {
		return out, cloud.ErrTooLarge
	}
	out.Data = data
	if ct := res.Header.Get("Content-Type"); ct != "" && !out.Exported {
		out.MIME = ct
	}
	return out, nil
}

// Save writes content as a new file under the connector's folder in My
// Drive. The folder and any subfolders are created on first use; a name
// already there gets a numbered suffix. Drive allows two files of one name
// in a folder, so there is no conflict mode to lean on: the name is chosen
// from a fresh listing and the upload names the parent explicitly.
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
	parent, err := d.ensureFolder(ctx, append([]string{cloud.Folder}, segs...))
	if err != nil {
		return cloud.Item{}, err
	}
	taken, err := d.childNames(ctx, parent)
	if err != nil {
		return cloud.Item{}, err
	}
	target := cloud.UniqueName(name, func(n string) bool { return taken[n] })

	// A multipart upload: the metadata part names the parent, the media
	// part carries the text.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	meta, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json; charset=UTF-8"}})
	_, _ = fmt.Fprintf(meta, `{"name":%s,"parents":[%s],"mimeType":%s}`, jsonString(target), jsonString(parent), jsonString(mime))
	media, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {mime}})
	_, _ = media.Write(content)
	_ = mw.Close()
	var f file
	err = d.do(ctx, http.MethodPost,
		d.upload+"/files?uploadType=multipart&supportsAllDrives=true&fields="+url.QueryEscape(fileFields),
		&body, "multipart/related; boundary="+mw.Boundary(), &f)
	if err != nil {
		return cloud.Item{}, err
	}
	return d.item(f), nil
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ensureFolder walks the segments from My Drive's root, creating each
// folder that is missing, and returns the last one's id. Every path it can
// produce starts with the connector's folder, because the caller puts it
// first.
func (d *Driver) ensureFolder(ctx context.Context, segs []string) (string, error) {
	parent := MyDrive
	for _, seg := range segs {
		q := url.Values{
			"q":        {"name = " + quote(seg) + " and " + quote(parent) + " in parents and mimeType = " + quote(mimeFolder) + " and trashed = false"},
			"pageSize": {"1"},
		}
		var res fileList
		if err := d.get(ctx, d.listQuery(q), &res); err != nil {
			return "", err
		}
		if len(res.Files) > 0 {
			parent = res.Files[0].ID
			continue
		}
		var created file
		body := map[string]any{"name": seg, "mimeType": mimeFolder, "parents": []string{parent}}
		if err := d.postJSON(ctx, d.base+"/files?fields="+url.QueryEscape(fileFields), body, &created); err != nil {
			return "", err
		}
		parent = created.ID
	}
	return parent, nil
}

// childNames lists the names in a folder. Drive is case-sensitive about
// names, so the suffix rule is too.
func (d *Driver) childNames(ctx context.Context, folderID string) (map[string]bool, error) {
	out := map[string]bool{}
	token := ""
	for pages := 0; pages < 50; pages++ {
		q := url.Values{"q": {quote(folderID) + " in parents and trashed = false"}, "pageSize": {"200"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var res fileList
		if err := d.get(ctx, d.listQuery(q), &res); err != nil {
			return nil, err
		}
		for _, f := range res.Files {
			out[f.Name] = true
		}
		if res.NextPageToken == "" {
			break
		}
		token = res.NextPageToken
	}
	return out, nil
}
