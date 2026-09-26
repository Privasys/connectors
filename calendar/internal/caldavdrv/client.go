// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package caldavdrv is the one driver: CalDAV (RFC 4791) over
// github.com/emersion/go-webdav, with either an app password or a bearer.
//
// It reads on demand and keeps nothing: the provider is the system of
// record, and what this process holds between two calls is a pooled HTTP
// connection and the list of the holder's calendars.
//
// Three things go-webdav does not do are done by hand here, and only those:
// the two PROPFINDs that find the principal and the calendar home (a provider
// may put them on another host, and a redirect must stay a PROPFIND), the
// one PROPFIND that reads a calendar's ctag and sync token for the change
// feed, and the conditional headers (If-Match, If-None-Match) that make an
// update of a stale id fail rather than overwrite.
package caldavdrv

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/caldav"
)

// ErrLogin is the server refusing the credential: the details are wrong,
// which no other server would fix.
var ErrLogin = errors.New("the calendar server refused the sign-in")

// ErrProviderSetup is the provider refusing the DEPLOYMENT, not the holder:
// the sign-in worked, but calendar access is switched off for the project
// that owns this connector's OAuth client. Google answers every CalDAV call
// with 403 SERVICE_DISABLED until its CalDAV API is enabled, which is a
// separate API from the Calendar API. Nothing the holder types can fix it,
// so it must not read as a refused sign-in.
var ErrProviderSetup = errors.New("the calendar provider has not switched on calendar access for this deployment")

// refusal reads a 401 or 403 and says which of the two it is. The provider's
// own explanation travels with a setup refusal, because it names what to
// switch on and where.
func refusal(res *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8<<10))
	res.Body.Close()
	if res.StatusCode == http.StatusForbidden && serviceDisabled(body) {
		return fmt.Errorf("%w: %s", ErrProviderSetup, providerMessage(body))
	}
	return fmt.Errorf("%w (%s)", ErrLogin, res.Status)
}

func serviceDisabled(body []byte) bool {
	s := string(body)
	return strings.Contains(s, "SERVICE_DISABLED") || strings.Contains(s, "accessNotConfigured") ||
		strings.Contains(s, "has not been used in project")
}

// providerMessage is Google's error message (or the start of the body), cut
// to its first sentence: enough to name the API and the project.
func providerMessage(body []byte) string {
	var g struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &g) == nil && g.Error.Message != "" {
		msg = g.Error.Message
	}
	if i := strings.Index(msg, ". "); i > 0 {
		msg = msg[:i+1]
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// Config opens one account.
type Config struct {
	// Endpoint is the CalDAV context URL: where discovery starts, or for
	// Google the principal itself.
	Endpoint string
	// Principal is the principal path when the provider does not discover
	// it. Empty means ask the server.
	Principal string
	// User is the holder's address, which is how "the holder is the host"
	// is told from the organiser.
	User string
	// Password is the app password for basic auth; Token is the bearer for
	// OAuth. One of the two.
	Password string
	Token    func(ctx context.Context) (string, error)
	// HTTPClient is the transport; nil is a default with a timeout.
	HTTPClient *http.Client
}

// transport is the webdav.HTTPClient: it adds the credential and any
// conditional headers the call put in its context, and nothing else.
type transport struct {
	inner    *http.Client
	user     string
	password string
	token    func(ctx context.Context) (string, error)
}

type headerKey struct{}

// withHeaders asks the transport to add headers to the request it sends.
func withHeaders(ctx context.Context, h http.Header) context.Context {
	return context.WithValue(ctx, headerKey{}, h)
}

func (t *transport) Do(req *http.Request) (*http.Response, error) {
	if t.token != nil {
		tok, err := t.token(req.Context())
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	} else {
		req.SetBasicAuth(t.user, t.password)
	}
	if h, ok := req.Context().Value(headerKey{}).(http.Header); ok {
		for k, vs := range h {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	return t.inner.Do(req)
}

// statusOf reads the HTTP status out of a go-webdav error, which begins with
// it ("404 Not Found: ..."); its own type is internal to that module.
func statusOf(err error) int {
	if err == nil {
		return 0
	}
	s := err.Error()
	if i := strings.IndexByte(s, ' '); i > 0 {
		if n, e := strconv.Atoi(s[:i]); e == nil && n >= 100 && n < 600 {
			return n
		}
	}
	return 0
}

// ---------------------------------------------------------------- PROPFIND

// multistatus is the part of a PROPFIND answer this driver reads.
type multistatus struct {
	XMLName   xml.Name `xml:"DAV: multistatus"`
	Responses []struct {
		Href      string `xml:"DAV: href"`
		Propstats []struct {
			Status string `xml:"DAV: status"`
			Prop   struct {
				CurrentUserPrincipal struct {
					Href string `xml:"DAV: href"`
				} `xml:"DAV: current-user-principal"`
				CalendarHomeSet struct {
					Hrefs []string `xml:"DAV: href"`
				} `xml:"urn:ietf:params:xml:ns:caldav calendar-home-set"`
				CTag      string `xml:"http://calendarserver.org/ns/ getctag"`
				SyncToken string `xml:"DAV: sync-token"`
			} `xml:"DAV: prop"`
		} `xml:"DAV: propstat"`
	} `xml:"DAV: response"`
}

const (
	propfindPrincipal = `<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:current-user-principal/></D:prop></D:propfind>`
	propfindHome      = `<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><C:calendar-home-set/></D:prop></D:propfind>`
	propfindSync      = `<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:" xmlns:CS="http://calendarserver.org/ns/"><D:prop><CS:getctag/><D:sync-token/></D:prop></D:propfind>`
)

// propfind issues one PROPFIND at depth 0, following a redirect as a
// PROPFIND (Go's client would turn it into a GET), and returns the answer
// with the URL it finally came from.
func (t *transport) propfind(ctx context.Context, target string, body string) (*multistatus, *url.URL, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, nil, err
	}
	for hop := 0; hop < 4; hop++ {
		req, err := http.NewRequestWithContext(ctx, "PROPFIND", u.String(), strings.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/xml; charset=utf-8")
		req.Header.Set("Depth", "0")
		res, err := t.Do(req)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case res.StatusCode >= 300 && res.StatusCode <= 399:
			loc, err := res.Location()
			res.Body.Close()
			if err != nil {
				return nil, nil, err
			}
			if loc.Scheme != "https" && u.Scheme == "https" {
				return nil, nil, errors.New("the server redirected the sign-in off https")
			}
			u = loc
			continue
		case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
			return nil, nil, refusal(res)
		case res.StatusCode != http.StatusMultiStatus && res.StatusCode != http.StatusOK:
			res.Body.Close()
			return nil, nil, fmt.Errorf("%d %s", res.StatusCode, http.StatusText(res.StatusCode))
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		var ms multistatus
		if err := xml.NewDecoder(bytes.NewReader(raw)).Decode(&ms); err != nil {
			return nil, nil, fmt.Errorf("the server's answer is not a multistatus: %w", err)
		}
		return &ms, u, nil
	}
	return nil, nil, errors.New("the server redirected too many times")
}

// resolve turns an href (a path, or a full URL on another host) into a URL
// against the one it was answered from.
func resolve(from *url.URL, href string) (*url.URL, error) {
	href = strings.TrimSpace(href)
	if href == "" {
		return nil, errors.New("empty href")
	}
	ref, err := url.Parse(href)
	if err != nil {
		return nil, err
	}
	return from.ResolveReference(ref), nil
}

// discoverHome finds the calendar home from the endpoint: the principal
// (given, or asked of the server), then the home set on the principal.
func (t *transport) discoverHome(ctx context.Context, endpoint, principal string) (*url.URL, error) {
	base, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	var principalURL *url.URL
	if principal != "" {
		principalURL, err = resolve(base, principal)
		if err != nil {
			return nil, err
		}
	} else {
		ms, from, err := t.propfind(ctx, endpoint, propfindPrincipal)
		if err != nil {
			return nil, err
		}
		href := ""
		for _, r := range ms.Responses {
			for _, ps := range r.Propstats {
				if ps.Prop.CurrentUserPrincipal.Href != "" {
					href = ps.Prop.CurrentUserPrincipal.Href
				}
			}
		}
		if href == "" {
			return nil, errors.New("the server names no principal for this account")
		}
		principalURL, err = resolve(from, href)
		if err != nil {
			return nil, err
		}
	}
	ms, from, err := t.propfind(ctx, principalURL.String(), propfindHome)
	if err != nil {
		return nil, err
	}
	for _, r := range ms.Responses {
		for _, ps := range r.Propstats {
			for _, h := range ps.Prop.CalendarHomeSet.Hrefs {
				if strings.TrimSpace(h) != "" {
					return resolve(from, h)
				}
			}
		}
	}
	return nil, errors.New("the server names no calendar home for this account")
}

// syncState reads a calendar's ctag and sync token: what the change feed
// compares between two looks.
func (t *transport) syncState(ctx context.Context, calendarURL string) (ctag, token string, err error) {
	ms, _, err := t.propfind(ctx, calendarURL, propfindSync)
	if err != nil {
		return "", "", err
	}
	for _, r := range ms.Responses {
		for _, ps := range r.Propstats {
			if ps.Prop.CTag != "" {
				ctag = ps.Prop.CTag
			}
			if ps.Prop.SyncToken != "" {
				token = ps.Prop.SyncToken
			}
		}
	}
	return ctag, token, nil
}

// ---------------------------------------------------------------- open

// calendar is one collection as this driver knows it.
type calendar struct {
	path     string
	name     string
	desc     string
	primary  bool
	readOnly bool
}

// Driver is one open account.
type Driver struct {
	cfg  Config
	t    *transport
	dav  *caldav.Client
	home *url.URL
	cals []calendar
	now  func() time.Time
}

// Open finds the holder's calendars and proves the credential on the way: a
// server that refuses the sign-in answers ErrLogin, one that cannot be
// reached answers with what went wrong.
func Open(ctx context.Context, cfg Config) (*Driver, error) {
	// Redirects are handled by propfind, as PROPFINDs. Go's client would
	// follow a 301 with a GET, which is how a well-known path answers a
	// discovery with a 404 from somewhere else.
	inner := &http.Client{Timeout: 30 * time.Second}
	if cfg.HTTPClient != nil {
		copied := *cfg.HTTPClient
		inner = &copied
	}
	inner.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t := &transport{inner: inner, user: cfg.User, password: cfg.Password, token: cfg.Token}
	home, err := t.discoverHome(ctx, cfg.Endpoint, cfg.Principal)
	if err != nil {
		return nil, err
	}
	// The go-webdav client is rooted at the home's own origin, so every
	// href the server answers with is a path on the host it belongs to.
	origin := &url.URL{Scheme: home.Scheme, Host: home.Host, Path: "/"}
	dav, err := caldav.NewClient(webdav.HTTPClient(t), origin.String())
	if err != nil {
		return nil, err
	}
	d := &Driver{cfg: cfg, t: t, dav: dav, home: home, now: time.Now}
	if err := d.refreshCalendars(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

// refreshCalendars lists the collections under the home that hold events.
func (d *Driver) refreshCalendars(ctx context.Context) error {
	found, err := d.dav.FindCalendars(ctx, d.home.Path)
	if err != nil {
		if statusOf(err) == http.StatusUnauthorized || statusOf(err) == http.StatusForbidden {
			return fmt.Errorf("%w (%v)", ErrLogin, err)
		}
		return err
	}
	var cals []calendar
	for _, c := range found {
		if !holdsEvents(c) {
			continue
		}
		cals = append(cals, calendar{path: c.Path, name: c.Name, desc: c.Description, readOnly: c.ReadOnly})
	}
	if len(cals) == 0 {
		return errors.New("signed in, but the account has no calendar that holds events")
	}
	// The primary calendar. CalDAV has no property for it, so: Google's
	// "events" collection when there is one, otherwise the first writable
	// calendar the server listed, which is what every client shows first.
	primary := -1
	for i, c := range cals {
		if strings.HasSuffix(strings.TrimSuffix(c.path, "/"), "/events") {
			primary = i
			break
		}
	}
	if primary < 0 {
		for i, c := range cals {
			if !c.readOnly {
				primary = i
				break
			}
		}
	}
	if primary < 0 {
		primary = 0
	}
	cals[primary].primary = true
	d.cals = cals
	return nil
}

func holdsEvents(c caldav.Calendar) bool {
	if len(c.SupportedComponentSet) == 0 {
		return true
	}
	for _, comp := range c.SupportedComponentSet {
		if strings.EqualFold(comp, "VEVENT") {
			return true
		}
	}
	return false
}

// calendarURL is the absolute URL of a collection path on the home's host.
func (d *Driver) calendarURL(path string) string {
	u := *d.home
	u.Path = path
	u.RawQuery = ""
	return u.String()
}

// Close drops what the driver holds, which is nothing but connections.
func (d *Driver) Close() error {
	if d.t != nil && d.t.inner != nil {
		d.t.inner.CloseIdleConnections()
	}
	return nil
}
