// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package api is the connector's HTTP surface: the tools an attested agent
// calls, over the shell every connector shares (the sdk's package connector).
//
// What is the calendar connector's here is the tool list, the account each
// tool runs against, the two drivers and the two sign-ins, the mapping of
// the drivers' errors to statuses, and the way a credential is connected
// (setup.go). Who the holder is, who a call acts for, the capability check,
// the credential refusal, the wallet-facing routes, the catalogue, the
// configure gate and the OAuth dance are the sdk's.
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
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	manifest "github.com/Privasys/connectors/calendar"
	"github.com/Privasys/connectors/calendar/internal/cal"
	"github.com/Privasys/connectors/calendar/internal/caldavdrv"
	"github.com/Privasys/connectors/calendar/internal/config"
	"github.com/Privasys/connectors/calendar/internal/discover"
	"github.com/Privasys/connectors/calendar/internal/graphdrv"
	"github.com/Privasys/connectors/calendar/internal/store"
	"github.com/Privasys/connectors/sdk/configure"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/feed"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
	"github.com/Privasys/connectors/sdk/oauth"
	"github.com/Privasys/connectors/sdk/provider"
	"github.com/Privasys/connectors/sdk/web"
)

// idleTTL is how long an unused account connection is kept.
const idleTTL = 20 * time.Minute

// The two providers this connector signs in with. The sdk knows no
// provider by name; these values are the whole of what it is told.
var (
	google = oauth.Provider{
		Name:     "Google",
		AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token",
		// The calendar, and the address of the account that signed in, so
		// the sign-in can be matched to the address the holder typed.
		Scopes: []string{discover.GoogleScope, "openid", "email"},
		// A refresh token is issued only with both. Without one the
		// credential would not outlive its first access token.
		AuthParams: map[string]string{"access_type": "offline", "prompt": "consent"},
	}
	microsoft = oauth.Provider{
		Name: "Microsoft",
		// The common tenant, so a work account and a personal account both
		// sign in through one registration.
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		// offline_access is what makes a refresh token come back; the rest
		// is the holder's address, and their calendars to read and to leave
		// a proposal on.
		Scopes: []string{"offline_access", "User.Read", "Calendars.ReadWrite"},
	}
)

// userinfoURL is where a Google sign-in's address is read from.
const userinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

type Server struct {
	svc   *connector.Service[store.Account]
	flows *oauth.Multi

	// The seams a test replaces: who hosts an address, the resolver that
	// finds a CalDAV server from one, the functions that open an account
	// at each driver, where a Google sign-in's address is read from, and
	// Microsoft's token endpoint.
	who               *provider.Resolver
	resolver          *discover.Resolver
	open              func(ctx context.Context, cfg caldavdrv.Config) (cal.Driver, error)
	openGraph         func(ctx context.Context, cfg graphdrv.Config) (graphDriver, error)
	userinfo          string
	microsoftTokenURL string
	http              *http.Client

	cfgMu sync.Mutex
	cfg   config.Config

	mu    sync.Mutex
	conns map[string]*conn
}

type conn struct {
	drv  cal.Driver
	used time.Time
}

// graphDriver is what the Graph seam hands back: the driver, and the
// address the account signs in as, which is what binds a sign-in to the
// address the holder typed.
type graphDriver interface {
	cal.Driver
	User() string
}

// New builds the connector over its stores. requireGrant is taken explicitly
// rather than defaulted, because the zero value being permissive would be
// exactly the wrong default.
func New(s store.Store, g grant.Store, requireGrant bool) *Server {
	srv := &Server{
		conns:             map[string]*conn{},
		who:               provider.Default(),
		resolver:          discover.Default,
		userinfo:          userinfoURL,
		microsoftTokenURL: microsoft.TokenURL,
		http:              &http.Client{Timeout: 30 * time.Second},
	}
	srv.open = func(ctx context.Context, cfg caldavdrv.Config) (cal.Driver, error) {
		return caldavdrv.Open(ctx, cfg)
	}
	srv.openGraph = func(ctx context.Context, cfg graphdrv.Config) (graphDriver, error) { return graphdrv.Open(ctx, cfg) }
	srv.flows = oauth.NewMulti(cal.Kind)
	gg := srv.flows.Add(store.ProviderGoogle, google)
	gg.Identify = srv.identifyGoogle
	ms := srv.flows.Add(store.ProviderMicrosoft, microsoft)
	ms.Identify = srv.identifyMicrosoft
	srv.svc = connector.New(connector.Options[store.Account]{
		Kind:     cal.Kind,
		Resource: "calendar",
		Name:     "Privasys Calendar Connector",
		Note: "Reads one calendar account for one attested agent, under a capability the holder approved on their device, " +
			"and leaves tentative proposals for the holder to confirm. It never sends an invitation. " +
			"There is no page to connect an account on: the holder's wallet asks for the address on the approval screen, " +
			"then holds the browser for a Google or Microsoft sign-in, or asks for an app password where there is no sign-in, " +
			"and this service keeps the credential only in memory.",
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

// SetConfigurable arms the configure endpoint, and takes the OAuth clients
// from the settings now and after every configure.
func (s *Server) SetConfigurable(g *configure.Gate[config.Config]) {
	g.OnApply = s.applyConfig
	if cur, set := g.Current(); set {
		s.applyConfig(cur)
	}
	s.svc.SetConfig(g)
}

func (s *Server) applyConfig(c config.Config) {
	s.cfgMu.Lock()
	s.cfg = c
	s.cfgMu.Unlock()
	s.flows.Flow(store.ProviderGoogle).SetClient(c.GoogleClientID, c.GoogleClientSecret)
	s.flows.Flow(store.ProviderMicrosoft).SetClient(c.MicrosoftClientID, c.MicrosoftClientSecret)
}

func (s *Server) config() config.Config {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	return s.cfg
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

// driverFor opens or reuses the account for one subject. Both drivers are
// stateless HTTP, so the change feed shares them: a held feed call does not
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
	drv, err := s.openAccount(ctx, sub, acct)
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

// openAccount is how an account is dialled: Graph with a bearer minted from
// the refresh token, Google's CalDAV with the same, or any other CalDAV
// server with the app password.
func (s *Server) openAccount(ctx context.Context, sub string, acct store.Account) (cal.Driver, error) {
	if acct.Provider == store.ProviderMicrosoft {
		return s.openGraph(ctx, graphdrv.Config{HTTP: s.http, Token: s.tokenSource(sub)})
	}
	cfg := caldavdrv.Config{Endpoint: acct.Endpoint, Principal: acct.Principal, User: acct.User, HTTPClient: s.http}
	if acct.Provider == store.ProviderGoogle {
		cfg.Token = s.tokenSource(sub)
	} else {
		cfg.Password = acct.Secret
	}
	return s.open(ctx, cfg)
}

// errTokenRefused is the provider no longer honouring the kept sign-in.
var errTokenRefused = errors.New("the provider no longer accepts the saved sign-in for this calendar; ask the user, then call request_access for their " +
	cal.Kind + " resource with ask_again true so they can sign in again on their device")

// tokenSource returns a bearer for the subject's account, refreshing it from
// the kept refresh token when it is about to expire. The refreshed tokens go
// back into memory; the refresh token itself stays what the wallet keeps.
func (s *Server) tokenSource(sub string) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		acct, err := s.credStore().Get(ctx, sub)
		if err != nil {
			return "", err
		}
		if acct.AccessToken != "" && time.Until(acct.Expiry) > time.Minute {
			return acct.AccessToken, nil
		}
		t, err := s.refresh(ctx, acct.Provider, acct.RefreshToken)
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

// refresh mints an access token from a refresh token, at the provider's
// token endpoint. Google's is the sdk's Refresh. Microsoft's token endpoint
// wants the scope named again on a refresh, which the sdk does not send,
// so that one is a plain form post here with the same client the flow
// holds, as the files connector does it.
func (s *Server) refresh(ctx context.Context, prov, refreshToken string) (oauth.Tokens, error) {
	if prov != store.ProviderMicrosoft {
		return s.flows.Flow(prov).Refresh(ctx, refreshToken)
	}
	if strings.TrimSpace(refreshToken) == "" {
		return oauth.Tokens{}, errors.New("no refresh token")
	}
	cfg := s.config()
	if !cfg.MicrosoftConfigured() {
		return oauth.Tokens{}, errors.New("this deployment has no OAuth client configured for Microsoft")
	}
	form := url.Values{
		"client_id": {cfg.MicrosoftClientID}, "client_secret": {cfg.MicrosoftClientSecret},
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		"scope": {strings.Join(microsoft.Scopes, " ")},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.microsoftTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauth.Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := s.http.Do(req)
	if err != nil {
		return oauth.Tokens{}, err
	}
	defer res.Body.Close()
	var body struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil && res.StatusCode == http.StatusOK {
		return oauth.Tokens{}, fmt.Errorf("microsoft: unreadable token answer: %w", err)
	}
	if res.StatusCode != http.StatusOK || body.AccessToken == "" {
		if body.Error != "" {
			return oauth.Tokens{}, fmt.Errorf("%w: %s", oauth.ErrRefused, strings.TrimSpace(body.Error+" "+body.ErrorDescription))
		}
		return oauth.Tokens{}, fmt.Errorf("microsoft: token endpoint answered %s", res.Status)
	}
	out := oauth.Tokens{AccessToken: body.AccessToken, RefreshToken: body.RefreshToken}
	if body.ExpiresIn > 0 {
		out.Expiry = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	}
	if out.RefreshToken == "" {
		out.RefreshToken = refreshToken
	}
	return out, nil
}

// Routes returns the mux. Tool endpoints mirror the manifest exactly.
func (s *Server) Routes() *http.ServeMux {
	m := http.NewServeMux()
	s.svc.Mount(m)
	s.flows.Routes(m)

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
	case errors.Is(err, caldavdrv.ErrProviderSetup):
		// Not the user's details: asking them again would change nothing.
		return connector.Errorf(http.StatusBadGateway, "calendar access is switched off for this deployment at the provider; "+
			"tell the user it is a setup problem on the service's side, not their account (%v)", err)
	case errors.Is(err, caldavdrv.ErrLogin), errors.Is(err, graphdrv.ErrLogin):
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
