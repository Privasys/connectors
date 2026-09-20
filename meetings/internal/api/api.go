// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package api is the connector's HTTP surface: the tools an attested agent
// calls, over the shell every connector shares (the sdk's package connector).
//
// What is the meetings connector's here is the tool list, the account each
// tool runs against, the two providers behind one driver interface, the
// mapping of the drivers' errors to statuses, the archive in the holder's
// Drive, and the way a credential is connected (setup.go). Who the holder
// is, who a call acts for, the capability check, the credential refusal,
// the wallet-facing routes, the catalogue, the configure gate and the OAuth
// dance are the sdk's.
//
// The tool surface is the smallest thing that does the job: list, read,
// keep, follow. There is no join, no start, no record and no invite, and
// every capability omitted is one a description cannot talk the model into
// using.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	manifest "github.com/Privasys/connectors/meetings"
	"github.com/Privasys/connectors/meetings/internal/archive"
	"github.com/Privasys/connectors/meetings/internal/config"
	"github.com/Privasys/connectors/meetings/internal/meet"
	"github.com/Privasys/connectors/meetings/internal/store"
	"github.com/Privasys/connectors/meetings/internal/teamsdrv"
	"github.com/Privasys/connectors/meetings/internal/zoomdrv"
	"github.com/Privasys/connectors/sdk/configure"
	"github.com/Privasys/connectors/sdk/connector"
	"github.com/Privasys/connectors/sdk/feed"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
	"github.com/Privasys/connectors/sdk/oauth"
	"github.com/Privasys/connectors/sdk/redact"
	"github.com/Privasys/connectors/sdk/vtt"
	"github.com/Privasys/connectors/sdk/web"
)

// idleTTL is how long an unused account connection is kept.
const idleTTL = 20 * time.Minute

// pageBytes caps one page of transcript text; offset pages through the
// rest. A day-long meeting is hundreds of kilobytes, and no model should
// be handed that in one answer.
const pageBytes = 48 << 10

// feedWindow and feedInterval are the change feed's: the last week of
// meetings, asked for every 30 seconds inside the held call.
const (
	feedWindow   = 7 * 24 * time.Hour
	feedInterval = 30 * time.Second
)

// The two providers, as the sdk's OAuth needs them. The sdk knows no
// provider by name; these values are the whole of what it is told. Zoom's
// scopes come from the configuration (see zoomProvider).
var (
	zoomAuthURL  = "https://zoom.us/oauth/authorize"
	zoomTokenURL = "https://zoom.us/oauth/token"
	microsoft    = oauth.Provider{
		Name:     "Microsoft",
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		// offline_access is what yields a refresh token; the rest is the
		// account, the calendar the meetings are found from, the online
		// meetings and their transcripts.
		Scopes: []string{"offline_access", "User.Read", "Calendars.Read", "OnlineMeetings.Read", "OnlineMeetingTranscript.Read.All"},
	}
)

func zoomProvider(scopes string) oauth.Provider {
	return oauth.Provider{
		Name:     "Zoom",
		AuthURL:  zoomAuthURL,
		TokenURL: zoomTokenURL,
		Scopes:   strings.Fields(scopes),
		// Zoom documents the client credentials as HTTP Basic at its token
		// endpoint.
		ClientAuthInHeader: true,
	}
}

type Server struct {
	svc   *connector.Service[store.Account]
	flows *oauth.Multi

	// The seams a test replaces: the API bases, the functions that open an
	// account at each provider, the archive, and the clock.
	zoomBase, graphBase string
	openZoom            func(ctx context.Context, cfg zoomdrv.Config) (meet.Driver, meet.Profile, error)
	openTeams           func(ctx context.Context, cfg teamsdrv.Config) (meet.Driver, meet.Profile, error)
	http                *http.Client
	now                 func() time.Time

	mu      sync.Mutex
	archive archive.Archive
	conns   map[string]*conn
}

type conn struct {
	drv  meet.Driver
	used time.Time
}

// New builds the connector over its stores. requireGrant is taken explicitly
// rather than defaulted, because the zero value being permissive would be
// exactly the wrong default.
func New(s store.Store, g grant.Store, requireGrant bool) *Server {
	srv := &Server{
		conns:     map[string]*conn{},
		zoomBase:  zoomdrv.DefaultAPIBase,
		graphBase: teamsdrv.DefaultAPIBase,
		http:      &http.Client{Timeout: 60 * time.Second},
		now:       time.Now,
		archive:   archive.None{},
	}
	srv.openZoom = func(ctx context.Context, cfg zoomdrv.Config) (meet.Driver, meet.Profile, error) {
		d, p, err := zoomdrv.Open(ctx, cfg)
		if err != nil {
			return nil, p, err
		}
		return d, p, nil
	}
	srv.openTeams = func(ctx context.Context, cfg teamsdrv.Config) (meet.Driver, meet.Profile, error) {
		d, p, err := teamsdrv.Open(ctx, cfg)
		if err != nil {
			return nil, p, err
		}
		return d, p, nil
	}
	srv.flows = oauth.NewMulti(meet.Kind)
	srv.installFlow(meet.ProviderZoom, zoomProvider(config.DefaultZoomScopes), "", "")
	srv.installFlow(meet.ProviderTeams, microsoft, "", "")
	srv.svc = connector.New(connector.Options[store.Account]{
		Kind:     meet.Kind,
		Resource: "meeting transcripts",
		Name:     "Privasys Meetings Connector",
		Note: "Reads the transcripts Zoom or Microsoft Teams produced for meetings the user took part in, from the user's own account, " +
			"for one attested agent under a capability the user approved on their device; keeps the ones the agent saves in the user's own Drive. " +
			"It never joins a meeting and never records one. There is no page to connect an account on: the user's wallet holds the browser " +
			"for the sign-in on the approval screen, and this service keeps the credential only in memory.",
		Credentials:   s,
		Grants:        g,
		RequireGrant:  requireGrant,
		Setup:         &setup{s: srv},
		Label:         func(a store.Account) string { return a.User },
		Prerequisites: srv.prerequisites,
		Manifest:      manifest.Manifest(),
		OnForget:      srv.dropConn,
		OnForgetAll:   srv.closeAll,
	})
	go srv.reapIdle()
	return srv
}

// installFlow registers one provider's flow, with this server's HTTP
// client and its identity probe.
func (s *Server) installFlow(slug string, p oauth.Provider, clientID, clientSecret string) *oauth.Flow {
	f := s.flows.Add(slug, p)
	f.HTTPClient = s.http
	f.Identify = s.identifier(slug)
	f.SetClient(clientID, clientSecret)
	return f
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
	// Zoom's scopes are a setting, so its flow is rebuilt; a sign-in in
	// flight at that moment starts again, which a reconfigure can afford.
	s.installFlow(meet.ProviderZoom, zoomProvider(c.ZoomScopes), c.ZoomClientID, c.ZoomClientSecret)
	s.flows.Flow(meet.ProviderTeams).SetClient(c.MicrosoftClientID, c.MicrosoftClientSecret)
}

// SetArchive installs where transcripts are kept: the holder's Drive on
// the platform, None off it.
func (s *Server) SetArchive(a archive.Archive) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a == nil {
		a = archive.None{}
	}
	s.archive = a
}

func (s *Server) getArchive() archive.Archive {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.archive
}

func (s *Server) credStore() store.Store { return s.svc.Credentials() }

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

// prerequisites is what the setup route lists for the wallet to complete
// first: this service's own folder in the holder's Drive.
func (s *Server) prerequisites(r *http.Request, sub string) []map[string]string {
	return s.getArchive().Prerequisite(r.Context(), sub)
}

// driverFor opens or reuses the account for one subject. Both drivers are
// stateless HTTP, so the change feed shares them: a held feed call does not
// delay a run's other calls.
func (s *Server) driverFor(ctx context.Context, sub string) (meet.Driver, error) {
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
	drv, _, err := s.open(ctx, acct.Provider, s.tokenSource(sub))
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

// open dials one provider with a bearer source and proves it.
func (s *Server) open(ctx context.Context, provider string, token func(context.Context) (string, error)) (meet.Driver, meet.Profile, error) {
	switch provider {
	case meet.ProviderZoom:
		return s.openZoom(ctx, zoomdrv.Config{APIBase: s.zoomBase, Token: token, HTTPClient: s.http})
	case meet.ProviderTeams:
		return s.openTeams(ctx, teamsdrv.Config{APIBase: s.graphBase, Token: token, HTTPClient: s.http, Now: s.now})
	}
	return nil, meet.Profile{}, fmt.Errorf("unknown provider %q", provider)
}

// errTokenRefused is the provider no longer honouring the kept sign-in.
var errTokenRefused = errors.New("the provider no longer accepts the saved sign-in for these meetings; ask the user, then call request_access for their " +
	meet.Kind + " resource with ask_again true so they can sign in again on their device")

// tokenSource returns a bearer for the subject's account, refreshing it
// from the kept refresh token when it is about to expire. The refreshed
// tokens go back into memory. A provider that rotates the refresh token
// (Zoom does) leaves the wallet holding the previous one; the next mint
// hands the wallet the current one to keep (setup.go).
func (s *Server) tokenSource(sub string) func(ctx context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		acct, err := s.credStore().Get(ctx, sub)
		if err != nil {
			return "", err
		}
		if acct.AccessToken != "" && time.Until(acct.Expiry) > time.Minute {
			return acct.AccessToken, nil
		}
		flow := s.flows.Flow(acct.Provider)
		if flow == nil {
			return "", fmt.Errorf("no sign-in flow for provider %q", acct.Provider)
		}
		t, err := flow.Refresh(ctx, acct.RefreshToken)
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
	s.flows.Routes(m)

	// Every tool needs read: what the holder granted is reading their
	// meetings. save_transcript writes, but only into this service's own
	// folder in the holder's Drive, which the holder approved separately
	// and can withdraw there; the capability it checks is still the
	// reading of the transcript it keeps.
	s.tool(m, "/tools/list_meetings", grant.Read, s.listMeetings)
	s.tool(m, "/tools/get_transcript", grant.Read, s.getTranscript)
	s.tool(m, "/tools/save_transcript", grant.Read, s.saveTranscript)
	s.tool(m, "/tools/changes", grant.Read, s.changes)
	s.tool(m, "/tools/account", grant.Read, s.account)
	return m
}

type handler func(ctx context.Context, sub string, drv meet.Driver, body json.RawMessage) (any, error)

// tool registers one tool through the shell, which does the acting-user
// check, the configure gate, the credential check and the capability check
// at both paths from one closure. What is added here is the account, opened
// or reused for the subject, and the driver's own errors given their status.
func (s *Server) tool(m *http.ServeMux, path string, need grant.Permission, h handler) {
	s.svc.Tool(m, path, need, func(ctx context.Context, sub string, body json.RawMessage) (any, error) {
		drv, err := s.driverFor(ctx, sub)
		if err != nil {
			return nil, status(err, "the meetings account is not reachable: ")
		}
		out, err := h(ctx, sub, drv, body)
		if err != nil {
			return nil, status(err, "")
		}
		return out, nil
	})
}

// status gives the drivers' and the archive's errors their HTTP status;
// anything else is the provider's fault.
func status(err error, prefix string) error {
	var needs *archive.NeedsFolder
	switch {
	case errors.Is(err, store.ErrNoAccount):
		return err
	case errors.Is(err, meet.ErrNotFound):
		return connector.Errorf(http.StatusNotFound, "%v", err)
	case errors.Is(err, meet.ErrNoTranscript):
		return connector.Errorf(http.StatusUnprocessableEntity, "%v: the provider has no transcript for it, because it was not recorded, transcription was off, or the transcript is still being produced", err)
	case errors.Is(err, errTokenRefused), errors.Is(err, meet.ErrLogin):
		return connector.Errorf(http.StatusBadGateway, "%v", errTokenRefused)
	case errors.As(err, &needs):
		return connector.Errorf(http.StatusPreconditionFailed, "%v", err)
	case errors.Is(err, archive.ErrNotConfigured):
		return connector.Errorf(http.StatusServiceUnavailable, "%v", err)
	case errors.Is(err, vtt.ErrNotVTT):
		return connector.Errorf(http.StatusBadGateway, "the provider's transcript is not WebVTT: %v", err)
	}
	if prefix != "" {
		return connector.Errorf(http.StatusBadGateway, "%s%v", prefix, err)
	}
	return err
}

// Handler builds the http.Handler for this server.
func (s *Server) Handler() http.Handler { return web.Logging(s.Routes()) }

// ---------------------------------------------------------------- tools

// window reads a [from, to) pair: RFC 3339 or a date, defaulting to the
// last seven days, bounded by meet.MaxWindow and by now.
func window(fromS, toS string, now time.Time) (time.Time, time.Time, error) {
	to := now
	if strings.TrimSpace(toS) != "" {
		t, err := parseTime(toS)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("to: %w", err)
		}
		to = t
	}
	from := to.Add(-feedWindow)
	if strings.TrimSpace(fromS) != "" {
		t, err := parseTime(fromS)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("from: %w", err)
		}
		from = t
		if strings.TrimSpace(toS) == "" {
			to = from.Add(feedWindow)
			if to.After(now) {
				to = now
			}
		}
	}
	if !to.After(from) {
		return time.Time{}, time.Time{}, errors.New("to must be after from")
	}
	if to.Sub(from) > meet.MaxWindow {
		return time.Time{}, time.Time{}, fmt.Errorf("the window is longer than %d days; ask for less", int(meet.MaxWindow.Hours()/24))
	}
	return from, to, nil
}

// parseTime accepts RFC 3339 and a bare date.
func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%q is not an RFC 3339 time or a date", s)
}

func (s *Server) listMeetings(ctx context.Context, _ string, drv meet.Driver, body json.RawMessage) (any, error) {
	var req struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	from, to, err := window(req.From, req.To, s.now())
	if err != nil {
		return nil, err
	}
	ms, err := drv.Meetings(ctx, from, to)
	if err != nil {
		return nil, err
	}
	if ms == nil {
		ms = []meet.Meeting{}
	}
	return map[string]any{"meetings": ms, "from": from, "to": to}, nil
}

type transcriptReq struct {
	MeetingID string `json:"meeting_id"`
	Format    string `json:"format"`
	Offset    int    `json:"offset"`
}

// fetch reads and parses one transcript.
func fetch(ctx context.Context, drv meet.Driver, meetingID string) (meet.Transcript, *vtt.Transcript, error) {
	if strings.TrimSpace(meetingID) == "" {
		return meet.Transcript{}, nil, errors.New("meeting_id is required")
	}
	t, err := drv.Transcript(ctx, strings.TrimSpace(meetingID))
	if err != nil {
		return meet.Transcript{}, nil, err
	}
	parsed, err := vtt.ParseBytes(t.VTT)
	if err != nil {
		return meet.Transcript{}, nil, err
	}
	return t, parsed, nil
}

// getTranscript answers the speaker-attributed text, or the raw WebVTT,
// credentials stripped, one page at a time.
func (s *Server) getTranscript(ctx context.Context, _ string, drv meet.Driver, body json.RawMessage) (any, error) {
	var req transcriptReq
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "vtt" {
		return nil, errors.New(`format must be "text" or "vtt"`)
	}
	if req.Offset < 0 {
		return nil, errors.New("offset must not be negative")
	}
	t, parsed, err := fetch(ctx, drv, req.MeetingID)
	if err != nil {
		return nil, err
	}
	full := parsed.Text()
	if format == "vtt" {
		full = string(t.VTT)
	}
	cleaned := redact.Apply(full)
	page, next := pageOf(cleaned.Text, req.Offset)
	m := t.Meeting
	m.Participants = mergeParticipants(m, parsed)
	out := map[string]any{
		"meeting":     m,
		"format":      format,
		"speakers":    nonNilStrings(parsed.Speakers()),
		"duration":    vtt.Clock(parsed.Duration()),
		"text":        page,
		"offset":      req.Offset,
		"total_bytes": len(cleaned.Text),
		"truncated":   next > 0,
		"redactions":  cleaned.Count,
	}
	if next > 0 {
		out["next_offset"] = next
	}
	return out, nil
}

// pageOf cuts one page out of the text at a line boundary, and says where
// the next page starts (0 when this was the last).
func pageOf(text string, offset int) (string, int) {
	if offset >= len(text) {
		return "", 0
	}
	rest := text[offset:]
	if len(rest) <= pageBytes {
		return rest, 0
	}
	cut := pageBytes
	if i := strings.LastIndex(rest[:cut], "\n"); i > 0 {
		cut = i + 1
	}
	return rest[:cut], offset + cut
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// mergeParticipants adds the transcript's speakers to what the provider
// listed, as people with a name only.
func mergeParticipants(m meet.Meeting, t *vtt.Transcript) []meet.Person {
	out := append([]meet.Person(nil), m.Participants...)
	seen := map[string]bool{}
	for _, p := range out {
		seen[strings.ToLower(p.Name)] = true
	}
	for _, sp := range t.Speakers() {
		if !seen[strings.ToLower(sp)] {
			seen[strings.ToLower(sp)] = true
			out = append(out, meet.Person{Name: sp})
		}
	}
	return out
}

// saveTranscript keeps the transcript in the holder's Drive.
func (s *Server) saveTranscript(ctx context.Context, sub string, drv meet.Driver, body json.RawMessage) (any, error) {
	var req transcriptReq
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	t, parsed, err := fetch(ctx, drv, req.MeetingID)
	if err != nil {
		return nil, err
	}
	saved, err := s.getArchive().Save(ctx, sub, t.Meeting, parsed, t.VTT)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"saved":   saved,
		"meeting": t.Meeting,
		"note":    "the transcript is in the user's own Drive, under their keys; this service keeps no copy",
	}, nil
}

// changes reports transcripts that became available since the cursor. The
// providers push nothing, so the held call asks for the last week's
// meetings every 30 seconds; the cursor is the newest transcript time seen.
func (s *Server) changes(ctx context.Context, _ string, drv meet.Driver, body json.RawMessage) (any, error) {
	var req feed.Request
	if err := web.Decode(body, &req); err != nil {
		return nil, err
	}
	since := time.Time{}
	if strings.TrimSpace(req.Since) != "" {
		t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(req.Since))
		if err != nil {
			return nil, fmt.Errorf("since: %w", err)
		}
		since = t
	} else {
		// A first call establishes the cursor: what is already there is
		// history, not a change.
		since = s.now()
	}
	var found []map[string]any
	newest := since
	_, err := feed.Poll(ctx, req.Wait(), feedInterval, func(ctx context.Context) (bool, error) {
		now := s.now()
		ms, err := drv.Meetings(ctx, now.Add(-feedWindow), now)
		if err != nil {
			return false, err
		}
		for _, m := range ms {
			if !m.HasTranscript || !m.TranscriptAt.After(since) {
				continue
			}
			found = append(found, map[string]any{"id": m.ID, "kind": "transcript_available", "title": m.Title, "start": m.Start, "transcript_at": m.TranscriptAt})
			if m.TranscriptAt.After(newest) {
				newest = m.TranscriptAt
			}
		}
		return len(found) > 0, nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		found = []map[string]any{}
	}
	return map[string]any{"changes": found, "cursor": newest.UTC().Format(time.RFC3339Nano)}, nil
}

func (s *Server) account(ctx context.Context, sub string, _ meet.Driver, _ json.RawMessage) (any, error) {
	a, err := s.credStore().Get(ctx, sub)
	if err != nil {
		return nil, err
	}
	st, err := s.getArchive().Status(ctx, sub)
	out := map[string]any{"account": a.Redacted(), "archive": st}
	if err != nil {
		out["archive_error"] = err.Error()
	}
	return out, nil
}
