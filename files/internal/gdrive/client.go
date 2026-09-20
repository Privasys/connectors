// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package gdrive is the Google driver: My Drive and shared drives through
// the Drive API v3, with a bearer the connector mints from the refresh
// token the wallet keeps.
//
// Only files.list, files.get (metadata, media and export), about, drives,
// the changes feed, and the two writes Save needs (a folder, a small
// multipart upload, both under the connector's own folder) are spoken here.
// Nothing in this package can delete, move, rename or share a file, because
// nothing in it sends those requests.
package gdrive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Privasys/connectors/files/internal/cloud"
)

// The API's two roots: metadata and listing, and uploads.
const (
	DefaultBase   = "https://www.googleapis.com/drive/v3"
	DefaultUpload = "https://www.googleapis.com/upload/drive/v3"
)

// MyDrive is the id this driver gives the holder's own drive. Google has no
// drive id for it (files there carry no driveId), and "root" is the alias
// the API accepts for its top folder.
const MyDrive = "root"

// Google's native document types, which have no bytes of their own and are
// read through an export.
const (
	mimeFolder       = "application/vnd.google-apps.folder"
	mimeDocument     = "application/vnd.google-apps.document"
	mimeSpreadsheet  = "application/vnd.google-apps.spreadsheet"
	mimePresentation = "application/vnd.google-apps.presentation"
)

// Config is how the driver reaches Drive.
type Config struct {
	// Base and Upload replace the defaults in a test.
	Base   string
	Upload string
	HTTP   *http.Client
	Token  cloud.TokenFunc
}

// Driver is one holder's Google account.
type Driver struct {
	cfg    Config
	base   string
	upload string
	acct   cloud.Account
}

// Open proves the token against Drive with about, which is also where the
// account's address and name come from.
func Open(ctx context.Context, cfg Config) (*Driver, error) {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if cfg.Token == nil {
		return nil, errors.New("gdrive: no token source")
	}
	d := &Driver{cfg: cfg, base: strings.TrimRight(cfg.Base, "/"), upload: strings.TrimRight(cfg.Upload, "/")}
	if d.base == "" {
		d.base = DefaultBase
	}
	if d.upload == "" {
		d.upload = DefaultUpload
	}
	var about struct {
		User struct {
			DisplayName  string `json:"displayName"`
			EmailAddress string `json:"emailAddress"`
		} `json:"user"`
	}
	if err := d.get(ctx, d.base+"/about?fields=user,storageQuota", &about); err != nil {
		return nil, err
	}
	if about.User.EmailAddress == "" {
		return nil, errors.New("gdrive: about names no account")
	}
	d.acct = cloud.Account{
		Provider: cloud.ProviderGoogle, User: strings.ToLower(about.User.EmailAddress), Name: about.User.DisplayName,
		DriveID: MyDrive, DriveType: "personal",
	}
	return d, nil
}

// Account is who was connected.
func (d *Driver) Account(context.Context) (cloud.Account, error) { return d.acct, nil }

// Close has nothing to close: the Drive API is stateless HTTP.
func (d *Driver) Close() error { return nil }

// ---------------------------------------------------------------- wire

// file is the subset of Drive's File this driver reads.
type file struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	MimeType          string    `json:"mimeType"`
	Size              string    `json:"size"`
	ModifiedTime      time.Time `json:"modifiedTime"`
	Version           string    `json:"version"`
	WebViewLink       string    `json:"webViewLink"`
	DriveID           string    `json:"driveId"`
	Trashed           bool      `json:"trashed"`
	Parents           []string  `json:"parents"`
	LastModifyingUser *struct {
		DisplayName string `json:"displayName"`
	} `json:"lastModifyingUser"`
}

// fileFields is what every listing asks for.
const fileFields = "id,name,mimeType,size,modifiedTime,version,webViewLink,driveId,trashed,parents,lastModifyingUser(displayName)"

type fileList struct {
	Files         []file `json:"files"`
	NextPageToken string `json:"nextPageToken"`
}

// item converts a file. The drive is the file's shared drive, or My Drive.
func (d *Driver) item(f file) cloud.Item {
	drive := f.DriveID
	if drive == "" {
		drive = MyDrive
	}
	out := cloud.Item{
		ID: cloud.EncodeID(drive, f.ID, f.Version), Name: f.Name, MIME: f.MimeType,
		Modified: f.ModifiedTime, WebURL: f.WebViewLink, Drive: drive,
	}
	out.Size, _ = strconv.ParseInt(f.Size, 10, 64)
	switch f.MimeType {
	case mimeFolder:
		out.Folder = true
		out.MIME = ""
	case mimeDocument:
		out.Native = "document"
	case mimeSpreadsheet:
		out.Native = "spreadsheet"
	case mimePresentation:
		out.Native = "presentation"
	}
	if f.LastModifyingUser != nil {
		out.ModifiedBy = f.LastModifyingUser.DisplayName
	}
	return out
}

// apiError is the body Drive answers an error with.
type apiError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

type statusError struct {
	status  int
	message string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("drive answered %d: %s", e.status, e.message)
}

func statusOf(err error) int {
	var se *statusError
	if errors.As(err, &se) {
		return se.status
	}
	return 0
}

// send is one request with the bearer. A 401 is cloud.ErrLogin, a 404 is
// cloud.ErrNotFound, anything else 4xx or 5xx a statusError with Drive's
// message.
func (d *Driver) send(ctx context.Context, method, target string, body io.Reader, contentType string) (*http.Response, error) {
	tok, err := d.cfg.Token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := d.cfg.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drive: %w", err)
	}
	if res.StatusCode >= 400 {
		defer res.Body.Close()
		var ae apiError
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&ae)
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("%w: %s", cloud.ErrLogin, ae.Error.Message)
		case http.StatusNotFound:
			return nil, fmt.Errorf("%w: %s", cloud.ErrNotFound, ae.Error.Message)
		}
		return nil, &statusError{status: res.StatusCode, message: ae.Error.Message}
	}
	return res, nil
}

func (d *Driver) do(ctx context.Context, method, target string, body io.Reader, contentType string, out any) error {
	res, err := d.send(ctx, method, target, body, contentType)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out); err != nil {
		return fmt.Errorf("drive: unreadable answer to %s: %w", method, err)
	}
	return nil
}

func (d *Driver) get(ctx context.Context, target string, out any) error {
	return d.do(ctx, http.MethodGet, target, nil, "", out)
}

func (d *Driver) postJSON(ctx context.Context, target string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return d.do(ctx, http.MethodPost, target, bytes.NewReader(b), "application/json", out)
}

// quote escapes a value for a Drive query string literal: backslashes and
// single quotes, which are the two characters the grammar reserves.
func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

// listQuery is a files.list URL with the parameters every listing shares:
// every drive included, the fields fixed.
func (d *Driver) listQuery(q url.Values) string {
	q.Set("fields", "nextPageToken,files("+fileFields+")")
	q.Set("supportsAllDrives", "true")
	q.Set("includeItemsFromAllDrives", "true")
	return d.base + "/files?" + q.Encode()
}
