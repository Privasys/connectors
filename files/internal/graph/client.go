// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package graph is the Microsoft driver: OneDrive and SharePoint document
// libraries through Microsoft Graph, with a bearer the connector mints from
// the refresh token the wallet keeps.
//
// Only the read endpoints, the delta feed, and the three writes Save needs
// (create a folder, upload a small file, both under the connector's own
// folder) are spoken here. Nothing in this package can delete, move, rename
// or share an item, because nothing in it sends those requests.
package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Privasys/connectors/files/internal/cloud"
)

// DefaultBase is Graph's v1.0 endpoint.
const DefaultBase = "https://graph.microsoft.com/v1.0"

// Config is how the driver reaches Graph.
type Config struct {
	// Base replaces DefaultBase in a test.
	Base  string
	HTTP  *http.Client
	Token cloud.TokenFunc
}

// Driver is one holder's Microsoft account.
type Driver struct {
	cfg  Config
	base string
	acct cloud.Account
}

// Open proves the token against Graph: who the account is (GET /me) and
// that it has a drive (GET /me/drive), which is the probe the sign-in and
// the kept token are both put through before the credential is kept.
func Open(ctx context.Context, cfg Config) (*Driver, error) {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if cfg.Token == nil {
		return nil, errors.New("graph: no token source")
	}
	base := strings.TrimRight(cfg.Base, "/")
	if base == "" {
		base = DefaultBase
	}
	d := &Driver{cfg: cfg, base: base}
	var me struct {
		DisplayName       string `json:"displayName"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := d.get(ctx, d.base+"/me?$select=displayName,mail,userPrincipalName", &me); err != nil {
		return nil, err
	}
	var drive driveItemDrive
	if err := d.get(ctx, d.base+"/me/drive?$select=id,driveType,name,webUrl", &drive); err != nil {
		return nil, err
	}
	user := strings.ToLower(strings.TrimSpace(me.Mail))
	if user == "" {
		user = strings.ToLower(strings.TrimSpace(me.UserPrincipalName))
	}
	d.acct = cloud.Account{
		Provider: cloud.ProviderMicrosoft, User: user, Name: me.DisplayName,
		DriveID: drive.ID, DriveType: drive.DriveType,
	}
	return d, nil
}

// Account is who was connected.
func (d *Driver) Account(context.Context) (cloud.Account, error) { return d.acct, nil }

// Close has nothing to close: Graph is stateless HTTP.
func (d *Driver) Close() error { return nil }

// ---------------------------------------------------------------- wire

type driveItemDrive struct {
	ID        string `json:"id"`
	DriveType string `json:"driveType"`
	Name      string `json:"name"`
	WebURL    string `json:"webUrl"`
}

// driveItem is the subset of Graph's driveItem this driver reads.
type driveItem struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	ETag                 string    `json:"eTag"`
	CTag                 string    `json:"cTag"`
	Size                 int64     `json:"size"`
	WebURL               string    `json:"webUrl"`
	LastModifiedDateTime time.Time `json:"lastModifiedDateTime"`
	File                 *struct {
		MimeType string `json:"mimeType"`
	} `json:"file"`
	Folder *struct {
		ChildCount int `json:"childCount"`
	} `json:"folder"`
	Root            *struct{} `json:"root"`
	Deleted         *struct{} `json:"deleted"`
	ParentReference *struct {
		DriveID string `json:"driveId"`
		Path    string `json:"path"`
	} `json:"parentReference"`
	LastModifiedBy *struct {
		User *struct {
			DisplayName string `json:"displayName"`
		} `json:"user"`
	} `json:"lastModifiedBy"`
}

// The fields every listing asks for, so a page carries what an Item needs
// and nothing more.
const itemSelect = "id,name,eTag,cTag,size,webUrl,lastModifiedDateTime,file,folder,root,deleted,parentReference,lastModifiedBy"

type page struct {
	Value     []driveItem `json:"value"`
	NextLink  string      `json:"@odata.nextLink"`
	DeltaLink string      `json:"@odata.deltaLink"`
}

// item converts a driveItem, taking the drive from its parent reference
// when the item does not say otherwise.
func (d *Driver) item(it driveItem, drive string) cloud.Item {
	if it.ParentReference != nil && it.ParentReference.DriveID != "" {
		drive = it.ParentReference.DriveID
	}
	out := cloud.Item{
		ID: cloud.EncodeID(drive, it.ID, it.ETag), Name: it.Name, Size: it.Size, WebURL: it.WebURL,
		Modified: it.LastModifiedDateTime, Drive: drive,
	}
	if it.Folder != nil {
		out.Folder = true
		out.Children = it.Folder.ChildCount
	}
	if it.File != nil {
		out.MIME = it.File.MimeType
	}
	if it.ParentReference != nil {
		// Graph's path is "/drive/root:/Documents/Reports"; the agent gets
		// "/Documents/Reports".
		if p := it.ParentReference.Path; p != "" {
			if i := strings.Index(p, "root:"); i >= 0 {
				p = p[i+len("root:"):]
			}
			if p == "" {
				p = "/"
			}
			out.Path, _ = url.PathUnescape(p)
		}
	}
	if it.LastModifiedBy != nil && it.LastModifiedBy.User != nil {
		out.ModifiedBy = it.LastModifiedBy.User.DisplayName
	}
	return out
}

// graphError is the body Graph answers an error with.
type graphError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// statusError carries a status the callers switch on.
type statusError struct {
	status  int
	code    string
	message string
}

func (e *statusError) Error() string {
	if e.code != "" {
		return fmt.Sprintf("graph answered %d %s: %s", e.status, e.code, e.message)
	}
	return fmt.Sprintf("graph answered %d: %s", e.status, e.message)
}

func statusOf(err error) int {
	var se *statusError
	if errors.As(err, &se) {
		return se.status
	}
	return 0
}

func codeOf(err error) string {
	var se *statusError
	if errors.As(err, &se) {
		return se.code
	}
	return ""
}

// do sends one request with the bearer and decodes a JSON answer into out.
// A 401 is the provider refusing the credential (cloud.ErrLogin); a 404 is
// cloud.ErrNotFound; anything else 4xx or 5xx is a statusError with what
// Graph said.
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
	if res.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out); err != nil {
		return fmt.Errorf("graph: unreadable answer to %s: %w", method, err)
	}
	return nil
}

// send is do without the decoding: the caller owns the body.
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
		return nil, fmt.Errorf("graph: %w", err)
	}
	if res.StatusCode >= 400 {
		defer res.Body.Close()
		var ge graphError
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&ge)
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("%w: %s", cloud.ErrLogin, strings.TrimSpace(ge.Error.Code+" "+ge.Error.Message))
		case http.StatusNotFound:
			return nil, fmt.Errorf("%w: %s", cloud.ErrNotFound, strings.TrimSpace(ge.Error.Code+" "+ge.Error.Message))
		}
		return nil, &statusError{status: res.StatusCode, code: ge.Error.Code, message: ge.Error.Message}
	}
	return res, nil
}

// download asks the content route with the bearer and, when Graph answers
// with a redirect to the pre-authenticated download URL, fetches that URL
// with no bearer at all. The client is told not to follow redirects for
// this one call, so the decision is made here and not by a rule about
// which hosts count as the same site.
func (d *Driver) download(ctx context.Context, target string) (*http.Response, error) {
	tok, err := d.cfg.Token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	noFollow := *d.cfg.HTTP
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := noFollow.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graph: %w", err)
	}
	if res.StatusCode/100 == 3 {
		loc := res.Header.Get("Location")
		res.Body.Close()
		if loc == "" {
			return nil, errors.New("graph: the content route redirected nowhere")
		}
		// Anywhere over https, or the fake in a test on Graph's own host.
		u, err := url.Parse(loc)
		if err != nil || (u.Scheme != "https" && !d.sameHost(u)) {
			return nil, errors.New("graph: the content route redirected to a URL this driver will not fetch")
		}
		plain, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
		if err != nil {
			return nil, err
		}
		res, err = d.cfg.HTTP.Do(plain)
		if err != nil {
			return nil, fmt.Errorf("graph: download: %w", err)
		}
	}
	if res.StatusCode >= 400 {
		defer res.Body.Close()
		var ge graphError
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&ge)
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("%w: %s", cloud.ErrLogin, ge.Error.Message)
		case http.StatusNotFound:
			return nil, fmt.Errorf("%w: %s", cloud.ErrNotFound, ge.Error.Message)
		}
		return nil, &statusError{status: res.StatusCode, code: ge.Error.Code, message: ge.Error.Message}
	}
	return res, nil
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

// ownURL checks that a link the provider handed back (a next page, a delta
// link) still points at Graph before it is followed with a bearer. The
// links travel through the agent as cursors, and a cursor is an input.
func (d *Driver) ownURL(link string) bool {
	return strings.HasPrefix(link, d.base+"/") || strings.HasPrefix(link, d.base+"?")
}

func (d *Driver) sameHost(u *url.URL) bool {
	b, err := url.Parse(d.base)
	return err == nil && u.Host == b.Host && u.Scheme == b.Scheme
}

// escapePath encodes a drive path for the root:/path: form.
func escapePath(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// quote escapes a value for an OData string literal.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
