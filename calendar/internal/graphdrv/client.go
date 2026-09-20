// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package graphdrv is the Microsoft driver: an Outlook calendar through
// Microsoft Graph, with a bearer the connector mints from the refresh token
// the wallet keeps. Microsoft serves no CalDAV, so a Microsoft account is
// the one the CalDAV driver cannot reach.
//
// Only the calendar list, the calendar view, one event by id, the delta
// query, and the three writes a proposal needs (create, patch, delete, each
// only on an event carrying this connector's own mark) are spoken here.
// Nothing in this package sends an invitation, because nothing in it puts
// an attendee on an event: a proposal names the people it is for in its
// text and asks for no response.
package graphdrv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/connectors/calendar/internal/cal"
)

// DefaultBase is Graph's v1.0 endpoint.
const DefaultBase = "https://graph.microsoft.com/v1.0"

// ErrLogin is Graph refusing the bearer: the sign-in is gone, which no
// retry would fix.
var ErrLogin = errors.New("Microsoft refused the sign-in")

// maxPages bounds how far a listing or a delta is followed in one call.
const maxPages = 20

// Config is how the driver reaches Graph.
type Config struct {
	// Base replaces DefaultBase in a test.
	Base string
	HTTP *http.Client
	// Token mints the bearer for each request, refreshing as needed.
	Token func(ctx context.Context) (string, error)
	// Now is the clock, for tests; nil is time.Now.
	Now func() time.Time
}

// Driver is one holder's Microsoft account.
type Driver struct {
	cfg  Config
	base string
	now  func() time.Time
	// user is the address the account signs in as, read at Open.
	user string
	// primary is the id of the default calendar, where a proposal lands
	// when none is named.
	primary string
}

// Open proves the bearer against Graph: who the account is (GET /me) and
// that its calendars can be read (GET /me/calendars), which is the probe
// the sign-in and the kept token are both put through before the
// credential is kept.
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
	d := &Driver{cfg: cfg, base: base, now: cfg.Now}
	if d.now == nil {
		d.now = time.Now
	}
	var me struct {
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := d.get(ctx, d.base+"/me?$select=mail,userPrincipalName", &me); err != nil {
		return nil, err
	}
	d.user = strings.ToLower(strings.TrimSpace(me.Mail))
	if d.user == "" {
		d.user = strings.ToLower(strings.TrimSpace(me.UserPrincipalName))
	}
	if _, err := d.Calendars(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

// User is the address the account signs in as, so the mint can check the
// sign-in was for the address the holder typed.
func (d *Driver) User() string { return d.user }

// Close has nothing to close: Graph is stateless HTTP.
func (d *Driver) Close() error { return nil }

// ownURL says whether a link Graph handed back (a next link, a delta link)
// still points at Graph. A cursor is an input when it comes back, and a
// bearer must never be sent where a cursor says.
func (d *Driver) ownURL(u string) bool {
	return strings.HasPrefix(u, d.base+"/") || strings.HasPrefix(u, d.base+"?")
}

// ---------------------------------------------------------------- wire

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

// get is one authenticated GET decoded into out.
func (d *Driver) get(ctx context.Context, target string, out any) error {
	return d.do(ctx, http.MethodGet, target, nil, out)
}

// do sends one request with the bearer and decodes a JSON answer into out.
// A 401 is the provider refusing the credential (ErrLogin); a 404 is
// cal.ErrNotFound; anything else 4xx or 5xx is a statusError with what
// Graph said. Times come back in UTC and bodies as text, by preference,
// so they parse one way and need no HTML stripped.
func (d *Driver) do(ctx context.Context, method, target string, body any, out any) error {
	tok, err := d.cfg.Token(ctx)
	if err != nil {
		return err
	}
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Prefer", `outlook.timezone="UTC", outlook.body-content-type="text"`)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := d.cfg.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("graph: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		var ge graphError
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&ge)
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("%w: %s", ErrLogin, strings.TrimSpace(ge.Error.Code+" "+ge.Error.Message))
		case http.StatusNotFound:
			return fmt.Errorf("%w: %s", cal.ErrNotFound, strings.TrimSpace(ge.Error.Code+" "+ge.Error.Message))
		}
		return &statusError{status: res.StatusCode, code: ge.Error.Code, message: ge.Error.Message}
	}
	if out == nil || res.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out); err != nil {
		return fmt.Errorf("graph: unreadable answer to %s: %w", method, err)
	}
	return nil
}

// ---------------------------------------------------------------- ids

// An event id encodes the calendar, Graph's event id and the changeKey it
// was read at. The changeKey is the point: an id from a listing addresses
// the version that was listed, so a later change makes the id fail
// (cal.ErrStale) rather than address what the event has become. Opaque to
// the agent, and to the harness. Graph gives each occurrence of a
// recurring event its own id, so one id per occurrence comes for free.
const idVersion = "g1"

type eventRef struct {
	cal       string
	id        string
	changeKey string
}

func (r eventRef) encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{idVersion, r.cal, r.id, r.changeKey}, "\x00")))
}

func parseID(id string) (eventRef, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(id))
	if err != nil {
		return eventRef{}, fmt.Errorf("%w: %v", cal.ErrBadID, err)
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 4 || parts[0] != idVersion || parts[2] == "" {
		return eventRef{}, cal.ErrBadID
	}
	return eventRef{cal: parts[1], id: parts[2], changeKey: parts[3]}, nil
}
