// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package api is the connector's HTTP surface: the tools an attested agent
// calls, over the shell every connector shares (the sdk's package connector).
//
// What is the calendar connector's here is the tool list, the account each
// tool runs against, the mapping of the driver's errors to statuses, and
// the two ways a credential is connected (setup.go). Who the holder is, who a
// call acts for, the capability check, the credential refusal, the
// wallet-facing routes, the catalogue, the configure gate and the OAuth
// dance are the sdk's.
//
// The tool surface is the smallest thing that does the job. There is no
// invite, no accept, no decline, and no change to an event the assistant did
// not propose: every capability omitted is one a description cannot talk
// the model into using.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	manifest "github.com/Privasys/connectors/calendar"
	"github.com/Privasys/connectors/calendar/internal/cal"
	"github.com/Privasys/connectors/calendar/internal/caldavdrv"
	"github.com/Privasys/connectors/calendar/internal/config"
	"github.com/Privasys/connectors/calendar/internal/discover"
	"github.com/Privasys/connectors/calendar/internal/store"
	"github.com/Privasys/connectors/sdk/configure"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/feed"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
	"github.com/Privasys/connectors/sdk/oauth"
	"github.com/Privasys/connectors/sdk/web"
)

// idleTTL is how long an unused account connection is kept.
const idleTTL = 20 * time.Minute

// google is the one provider this connector signs in with. The sdk knows no
// provider by name; this value is the whole of what it is told.
var google = oauth.Provider{
	Name:     "Google",
	AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
	TokenURL: "https://oauth2.googleapis.com/token",
	// The calendar, and the address of the account that signed in, so the
	// sign-in can be matched to the address the holder typed.
	Scopes: []string{discover.GoogleScope, "openid", "email"},
	// A refresh token is issued only with both. Without one the credential
	// would not outlive its first access token.
	AuthParams: map[string]string{"access_type": "offline", "prompt": "consent"},
}

// userinfoURL is where the signed-in account's address is read from.
const userinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

type Server struct {
	svc  *connector.Service[store.Account]
	flow *oauth.Flow

	// The seams a test replaces: the resolver that finds a server from an
	// address, the function that opens an account, and where the signed-in
	// address is read from.
	resolver *discover.Resolver
	open     func(ctx context.Context, cfg caldavdrv.Config) (cal.Driver, error)
	userinfo string
	http     *http.Client

	mu    sync.Mutex
	conns map[string]*conn
}

type conn struct {
	drv  cal.Driver
	used time.Time
}

// New builds the connector over its stores. requireGrant is taken explicitly
// rather than defaulted, because the zero value being permissive would be
// exactly the wrong default.
func New(s store.Store, g grant.Store, requireGrant bool) *Server {
	srv := &Server{
		conns:    map[string]*conn{},
		resolver: discover.Default,
		userinfo: userinfoURL,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
	srv.open = func(ctx context.Context, cfg caldavdrv.Config) (cal.Driver, error) {
		return caldavdrv.Open(ctx, cfg)
	}
	srv.flow = oauth.New(google, cal.Kind)
	srv.flow.Identify = srv.identify
	srv.svc = connector.New(connector.Options[store.Account]{
		Kind:     cal.Kind,
		Resource: "calendar",
		Name:     "Privasys Calendar Connector",
		Note: "Reads one calendar account for one attested agent, under a capability the holder approved on their device, " +
			"and leaves tentative proposals for the holder to confirm. It never sends an invitation. " +
			"There is no page to connect an account on: the holder's wallet asks on the approval screen, " +
			"or holds the browser for a Google sign-in, and this service keeps the credential only in memory.",
		Credentials:  s,
		Grants:       g,
		RequireGrant: requireGrant,
		Setup:        &setup{s: srv},
		Label:        func(a store.Account) string { return a.User },
		Manifest:     manifest.Manifest(),
		OnForget:     srv.dropConn,
		OnForgetAll:  srv.closeAll,
	})
	go srv.reapIdle()
	return srv
}

// SetVerifier installs the holder-token verifier.
func (s *Server) SetVerifier(v holder.Verifier) { s.svc.SetVerifier(v) }

// SetConfigurable arms the configure endpoint, and takes the OAuth client
// from the settings now and after every configure.
func (s *Server) SetConfigurable(g *configure.Gate[config.Config]) {
	g.OnApply = s.applyConfig
	if cur, set := g.Current(); set {
		s.applyConfig(cur)
	}
	s.svc.SetConfig(g)
}

func (s *Server) applyConfig(c config.Config) {
	s.flow.SetClient(c.OAuthClientID, c.OAuthClientSecret)
}

func (s *Server) credStore() store.Store  { return s.svc.Credentials() }
func (s *Server) grantStore() grant.Store { return s.svc.Grants() }

// Close forgets every credential and closes every account connection.
func (s *Server) Close() error { return s.svc.Close() }

func (s *Server) reapIdle() {
	for range time.Tick(time.Minute) {
		s.mu.Lock()
		for sub, c := range s.conns {
			if time.Since(c.used) > idleTTL {
				_ = c.drv.Close()
				delete(s.conns, sub)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Server) dropConn(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.conns[sub]; ok {
		_ = c.drv.Close()
		delete(s.conns, sub)
	}
}

func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sub, c := range s.conns {
		_ = c.drv.Close()
		delete(s.conns, sub)
	}
}

// driverFor opens or reuses the account for one subject. A CalDAV driver is
// stateless HTTP, so the change feed shares it: a held feed call does not
// delay a run's other calls the way a parked IMAP connection did.
func (s *Server) driverFor(ctx context.Context, sub string) (cal.Driver, error) {
	s.mu.Lock()
	if c, ok := s.conns[sub]; ok {
		c.used = time.Now()
		s.mu.Unlock()
		return c.drv, nil
	}
	s.mu.Unlock()

	acct, err := s.credStore().Get(ctx, sub)
	if err != nil {
		return nil, err
	}
	drv, err := s.open(ctx, s.driverConfig(sub, acct))
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.conns[sub]; ok { // lost a race; keep the winner
		_ = drv.Close()
		c.used = time.Now()
		return c.drv, nil
	}
	s.conns[sub] = &conn{drv: drv, used: time.Now()}
	return drv, nil
}

// driverConfig is how an account is dialled: an app password, or a bearer
// minted from the refresh token as needed.
func (s *Server) driverConfig(sub string, acct store.Account) caldavdrv.Config {
	cfg := caldavdrv.Config{Endpoint: acct.Endpoint, Principal: acct.Principal, User: acct.User, HTTPClient: s.http}
	if acct.Provider == store.ProviderGoogle {
		cfg.Token = s.tokenSource(sub)
	} else {
		cfg.Password = acct.Secret
	}
	return cfg
}

// errTokenRefused is Google no longer honouring the kept sign-in.
var errTokenRefused = errors.New("Google no longer accepts the saved sign-in for this calendar; ask the user, then call request_access for their " +
	cal.Kind + " resource with ask_again true so they can sign in again on their device")

// tokenSource returns a bearer for the subject's Google account, refreshing
// it from the kept refresh token when it is about to expire. The refreshed
// tokens go back into memory; the refresh token itself stays what the
// wallet keeps.
func (s *Server) tokenSource(sub string) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		acct, err := s.credStore().Get(ctx, sub)
		if err != nil {
			return "", err
		}
		if acct.AccessToken != "" && time.Until(acct.Expiry) > time.Minute {
			return acct.AccessToken, nil
		}
		t, err := s.flow.Refresh(ctx, acct.RefreshToken)
		if err != nil {
			if errors.Is(err, oauth.ErrRefused) {
				return "", errTokenRefused
			}
			return "", err
		}
		acct.AccessToken, acct.Expiry = t.AccessToken, t.Expiry
		if t.RefreshToken != "" {
			acct.RefreshToken = t.RefreshToken
		}
		_ = s.credStore().Put(ctx, sub, acct)
		return t.AccessToken, nil
	}
}

// Routes returns the mux. Tool endpoints mirror the manifest exactly.
func (s *Server) Routes() *http.ServeMux {
	m := http.NewServeMux()
	s.svc.Mount(m)
	s.flow.Routes(m)

	// The permission each tool needs. Reading and writing are different
	// sentences on the holder's approval screen, so they are different checks
	// here: a holder who approved read-only must not find the agent
	// proposing.
	s.tool(m, "/tools/list_calendars", grant.Read, s.listCalendars)
	s.tool(m, "/tools/list_events", grant.Read, s.listEvents)
	s.tool(m, "/tools/get_event", grant.Read, s.getEvent)
	s.tool(m, "/tools/search", grant.Read, s.search)
	s.tool(m, "/tools/free_busy", grant.Read, s.freeBusy)
	s.tool(m, "/tools/propose_event", grant.Write, s.proposeEvent)
	s.tool(m, "/tools/update_event", grant.Write, s.updateEvent)
	s.tool(m, "/tools/delete_event", grant.Write, s.deleteEvent)
	s.tool(m, "/tools/changes", grant.Read, s.changes)
	s.tool(m, "/tools/account", grant.Read, s.account)
	return m
}

type handler func(ctx context.Context, sub string, drv cal.Driver, body json.RawMessage) (any, error)

// tool registers one tool through the shell, which does the acting-user
// check, the configure gate, the credential check and the capability check
// at both paths from one closure. What is added here is the account, opened
// or reused for the subject, and the driver's own errors given their status.
func (s *Server) tool(m *http.ServeMux, path string, need grant.Permission, h handler) {
	s.svc.Tool(m, path, need, func(ctx context.Context, sub string, body json.RawMessage) (any, error) {
		drv, err := s.driverFor(ctx, sub)
		if err != nil {
			return nil, status(err, "the calendar account is not reachable: ")
		}
		out, err := h(ctx, sub, drv, body)
		if err != nil {
			return nil, status(err, "")
		}
		return out, nil
	})
}

// status gives the driver's errors their HTTP status; anything else is the
// provider's fault.
func status(err error, prefix string) error {
	switch {
	case errors.Is(err, store.ErrNoAccount):
		return err
	case errors.Is(err, cal.ErrNotFound):
		return connector.Errorf(http.StatusNotFound, "%v", err)
	case errors.Is(err, cal.ErrStale):
		return connector.Errorf(http.StatusConflict, "%v", err)
	case errors.Is(err, cal.ErrNotProposed):
		return connector.Errorf(http.StatusUnprocessableEntity, "%v", err)
	case errors.Is(err, cal.ErrBadID):
		return connector.Errorf(http.StatusBadRequest, "%v", err)
	case errors.Is(err, errTokenRefused):
		return connector.Errorf(http.StatusBadGateway, "%v", err)
	case errors.Is(err, caldavdrv.ErrLogin):
		return connector.Errorf(http.StatusBadGateway, "the calendar server no longer accepts the saved details; ask the user, then call request_access for their "+
			cal.Kind+" resource with ask_again true so their device sends them afresh (%v)", err)
	}
	if prefix != "" {
		return connector.Errorf(http.StatusBadGateway, "%s%v", prefix, err)
	}
	return err
}

// Handler builds the http.Handler for this server.
func (s *Server) Handler() http.Handler { return web.Logging(s.Routes()) }

// ---------------------------------------------------------------- tools

// window reads a [from, to) pair: RFC 3339 or a date, defaulting to now and
// to `span` after from, bounded by cal.MaxWindow. Dates are whole days.
func window(fromS, toS string, span time.Duration, now time.Time) (time.Time, time.Time, error) {
	from := now
	if strings.TrimSpace(fromS) != "" {
		t, _, err := parseTime(fromS)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("from: %w", err)
		}
		from = t
	}
	to := from.Add(span)
	if strings.TrimSpace(toS) != "" {
		t, _, err := parseTime(toS)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("to: %w", err)
		}
		to = t
	}
	if !to.After(from) {
		return time.Time{}, time.Time{}, errors.New("to must be after from")
	}
	if to.Sub(from) > cal.MaxWindow {
		return time.Time{}, time.Time{}, fmt.Errorf("the window is longer than %d days; ask for less", int(cal.MaxWindow.Hours()/24))
	}
	return from, to, nil
}

// parseTime accepts RFC 3339 and a bare date, and says which it was.
func parseTime(s string) (t time.Time, dateOnly bool, err error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, false, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, true, nil
	}
	return time.Time{}, false, fmt.Errorf("%q is not an RFC 3339 time or a date", s)
}

func (s *Server) listCalendars(ctx context.Context, _ string, drv cal.Driver, _ json.RawMessage) (any, error) {
	cals, err := drv.Calendars(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"calendars": cals}, nil
}

type windowReq struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Calendar string `json:"calendar"`
}

func (s *Server) listEvents(ctx context.Context, _ string, drv cal.Driver, body json.RawMessage) (any, error) {
	var req windowReq
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	from, to, err := window(req.From, req.To, 7*24*time.Hour, time.Now())
	if err != nil {
		return nil, err
	}
	evs, err := drv.Events(ctx, req.Calendar, from, to)
	if err != nil {
		return nil, err
	}
	return map[string]any{"events": nonNil(evs), "from": from, "to": to}, nil
}

func nonNil(evs []cal.Event) []cal.Event {
	if evs == nil {
		return []cal.Event{}
	}
	return evs
}

func (s *Server) getEvent(ctx context.Context, _ string, drv cal.Driver, body json.RawMessage) (any, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.ID) == "" {
		return nil, errors.New("id is required")
	}
	return drv.Get(ctx, req.ID)
}

// search is a windowed filter: every word of the query must appear in the
// title, the location, the description, an attendee or the organiser.
func (s *Server) search(ctx context.Context, _ string, drv cal.Driver, body json.RawMessage) (any, error) {
	var req struct {
		windowReq
		Query string `json:"query"`
	}
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	words := strings.Fields(strings.ToLower(req.Query))
	if len(words) == 0 {
		return nil, errors.New("query is required")
	}
	from, to, err := window(req.From, req.To, 31*24*time.Hour, time.Now())
	if err != nil {
		return nil, err
	}
	evs, err := drv.Events(ctx, req.Calendar, from, to)
	if err != nil {
		return nil, err
	}
	hits := []cal.Event{}
	for _, ev := range evs {
		if matches(ev, words) {
			hits = append(hits, ev)
		}
	}
	return map[string]any{"events": hits, "from": from, "to": to}, nil
}

func matches(ev cal.Event, words []string) bool {
	var b strings.Builder
	b.WriteString(ev.Title + "\n" + ev.Location + "\n" + ev.Description + "\n")
	for _, a := range ev.Attendees {
		b.WriteString(a.Name + " " + a.Address + "\n")
	}
	if ev.Organiser != nil {
		b.WriteString(ev.Organiser.Name + " " + ev.Organiser.Address)
	}
	hay := strings.ToLower(b.String())
	for _, w := range words {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

// freeBusy merges the holder's busy time in a window. Cancelled events,
// events that show as free, and the assistant's own proposals (tentative,
// unconfirmed) do not block.
func (s *Server) freeBusy(ctx context.Context, _ string, drv cal.Driver, body json.RawMessage) (any, error) {
	var req windowReq
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	from, to, err := window(req.From, req.To, 7*24*time.Hour, time.Now())
	if err != nil {
		return nil, err
	}
	evs, err := drv.Events(ctx, "", from, to)
	if err != nil {
		return nil, err
	}
	return map[string]any{"busy": busyIntervals(evs, from, to), "from": from, "to": to}, nil
}

func busyIntervals(evs []cal.Event, from, to time.Time) []cal.Busy {
	var raw []cal.Busy
	for _, ev := range evs {
		if ev.Free || ev.Status == "cancelled" || ev.Proposed {
			continue
		}
		start, end := ev.Start, ev.End
		if start.Before(from) {
			start = from
		}
		if end.After(to) {
			end = to
		}
		if end.After(start) {
			raw = append(raw, cal.Busy{Start: start, End: end})
		}
	}
	sort.Slice(raw, func(i, j int) bool { return raw[i].Start.Before(raw[j].Start) })
	out := []cal.Busy{}
	for _, b := range raw {
		if n := len(out); n > 0 && !b.Start.After(out[n-1].End) {
			if b.End.After(out[n-1].End) {
				out[n-1].End = b.End
			}
			continue
		}
		out = append(out, b)
	}
	return out
}

type proposeReq struct {
	Title       string   `json:"title"`
	Start       string   `json:"start"`
	End         string   `json:"end"`
	Description string   `json:"description"`
	Location    string   `json:"location"`
	Calendar    string   `json:"calendar"`
	Attendees   []string `json:"attendees"`
	RunID       string   `json:"run_id"`
}

func (s *Server) proposeEvent(ctx context.Context, _ string, drv cal.Driver, body json.RawMessage) (any, error) {
	var req proposeReq
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Title) == "" || req.Start == "" || req.End == "" {
		return nil, errors.New("title, start and end are all required")
	}
	start, startDate, err := parseTime(req.Start)
	if err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	end, endDate, err := parseTime(req.End)
	if err != nil {
		return nil, fmt.Errorf("end: %w", err)
	}
	if startDate != endDate {
		return nil, errors.New("start and end must both be times, or both be dates for an all-day event")
	}
	ev, err := drv.Propose(ctx, req.Calendar, cal.Proposal{
		Title: strings.TrimSpace(req.Title), Description: req.Description, Location: req.Location,
		Start: start, End: end, AllDay: startDate, Attendees: req.Attendees, Ref: strings.TrimSpace(req.RunID),
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"event": ev,
		"note":  "the event is tentative and nobody has been invited; the user confirms it in their own calendar",
	}, nil
}

func (s *Server) updateEvent(ctx context.Context, _ string, drv cal.Driver, body json.RawMessage) (any, error) {
	var req struct {
		ID          string   `json:"id"`
		Title       *string  `json:"title"`
		Start       *string  `json:"start"`
		End         *string  `json:"end"`
		Description *string  `json:"description"`
		Location    *string  `json:"location"`
		Attendees   []string `json:"attendees"`
	}
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.ID) == "" {
		return nil, errors.New("id is required")
	}
	p := cal.Patch{Title: req.Title, Description: req.Description, Location: req.Location, Attendees: req.Attendees}
	if req.Start != nil {
		t, _, err := parseTime(*req.Start)
		if err != nil {
			return nil, fmt.Errorf("start: %w", err)
		}
		p.Start = &t
	}
	if req.End != nil {
		t, _, err := parseTime(*req.End)
		if err != nil {
			return nil, fmt.Errorf("end: %w", err)
		}
		p.End = &t
	}
	if p.Title == nil && p.Start == nil && p.End == nil && p.Description == nil && p.Location == nil && p.Attendees == nil {
		return nil, errors.New("nothing to change")
	}
	return drv.Update(ctx, req.ID, p)
}

func (s *Server) deleteEvent(ctx context.Context, _ string, drv cal.Driver, body json.RawMessage) (any, error) {
	var req struct {
		ID string `json:"id"`
	}
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.ID) == "" {
		return nil, errors.New("id is required")
	}
	if err := drv.Delete(ctx, req.ID); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (s *Server) changes(ctx context.Context, _ string, drv cal.Driver, body json.RawMessage) (any, error) {
	var req feed.Request
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	changes, cursor, err := drv.Changes(ctx, req.Since, req.Wait())
	if err != nil {
		return nil, err
	}
	if changes == nil {
		changes = []cal.Change{}
	}
	return map[string]any{"changes": changes, "cursor": cursor}, nil
}

func (s *Server) account(ctx context.Context, sub string, drv cal.Driver, _ json.RawMessage) (any, error) {
	a, err := s.credStore().Get(ctx, sub)
	if err != nil {
		return nil, err
	}
	cals, err := drv.Calendars(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"account": a.Redacted(), "calendars": cals}, nil
}
