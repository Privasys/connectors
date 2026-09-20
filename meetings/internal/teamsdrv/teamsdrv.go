// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package teamsdrv reads the transcripts Microsoft Teams produced for
// meetings the holder was in, through Microsoft Graph with the holder's
// OAuth bearer.
//
// Graph has no "my meetings with a transcript" call, so a listing is built
// from the calendar: events in the window that carry a Teams join link,
// each resolved to its online meeting by that link, and each online
// meeting asked for its transcripts. A meeting with none is listed as
// having none. Nothing here can create, join or record a meeting.
package teamsdrv

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
	"time"

	"github.com/Privasys/connectors/meetings/internal/meet"
)

// DefaultAPIBase is Microsoft Graph.
const DefaultAPIBase = "https://graph.microsoft.com/v1.0"

// maxTranscript bounds a download; a transcript is text.
const maxTranscript = 16 << 20

// maxPages bounds how far a calendar listing is followed.
const maxPages = 20

// Config is how the driver dials.
type Config struct {
	// APIBase is Graph's origin and version prefix; a test points it at a
	// fake. Empty is DefaultAPIBase.
	APIBase string
	// Token mints the bearer for each request, refreshing as needed.
	Token func(ctx context.Context) (string, error)
	// HTTPClient reaches Graph; nil is a default.
	HTTPClient *http.Client
	// Now is the clock, for tests; nil is time.Now.
	Now func() time.Time
}

// Driver is one Microsoft account.
type Driver struct {
	base  string
	token func(ctx context.Context) (string, error)
	http  *http.Client
	now   func() time.Time
}

// Open proves the bearer with one call and returns the driver and the
// account it signs in as.
func Open(ctx context.Context, cfg Config) (*Driver, meet.Profile, error) {
	if cfg.Token == nil {
		return nil, meet.Profile{}, errors.New("teams: no token source")
	}
	base := strings.TrimRight(cfg.APIBase, "/")
	if base == "" {
		base = DefaultAPIBase
	}
	d := &Driver{base: base, token: cfg.Token, http: cfg.HTTPClient, now: cfg.Now}
	if d.http == nil {
		d.http = &http.Client{Timeout: 60 * time.Second}
	}
	if d.now == nil {
		d.now = time.Now
	}
	var me struct {
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
		DisplayName       string `json:"displayName"`
	}
	if err := d.get(ctx, d.base+"/me", &me); err != nil {
		return nil, meet.Profile{}, err
	}
	addr := me.Mail
	if addr == "" {
		addr = me.UserPrincipalName
	}
	return d, meet.Profile{Address: strings.ToLower(addr), Name: me.DisplayName}, nil
}

func (d *Driver) Close() error { return nil }

func (d *Driver) request(ctx context.Context, u string, accept string) (*http.Response, error) {
	tok, err := d.token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", accept)
	// Times in UTC, whatever the mailbox's zone, so they parse one way.
	req.Header.Set("Prefer", `outlook.timezone="UTC"`)
	res, err := d.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graph: %w", err)
	}
	return res, nil
}

// get performs one authenticated GET and decodes the JSON answer.
func (d *Driver) get(ctx context.Context, u string, out any) error {
	res, err := d.request(ctx, u, "application/json")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if err := status(res); err != nil {
		return err
	}
	return json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out)
}

// status maps Graph's refusals: a 401 is the sign-in, a 404 the meeting,
// anything else is the provider's fault.
func status(res *http.Response) error {
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return meet.ErrLogin
	case res.StatusCode == http.StatusNotFound:
		return meet.ErrNotFound
	case res.StatusCode/100 != 2:
		body, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("graph answered %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Graph's shapes, the fields this driver reads.
type (
	dateTimeZone struct {
		DateTime string `json:"dateTime"`
		TimeZone string `json:"timeZone"`
	}
	emailAddress struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	}
	recipient struct {
		EmailAddress emailAddress `json:"emailAddress"`
	}
	event struct {
		ID            string       `json:"id"`
		Subject       string       `json:"subject"`
		Start         dateTimeZone `json:"start"`
		End           dateTimeZone `json:"end"`
		Organizer     *recipient   `json:"organizer"`
		Attendees     []recipient  `json:"attendees"`
		IsOnline      bool         `json:"isOnlineMeeting"`
		OnlineMeeting *struct {
			JoinURL string `json:"joinUrl"`
		} `json:"onlineMeeting"`
		OnlineMeetingURL string `json:"onlineMeetingUrl"`
	}
	identitySet struct {
		User *struct {
			DisplayName string `json:"displayName"`
		} `json:"user"`
	}
	meetingParticipant struct {
		UPN      string      `json:"upn"`
		Identity identitySet `json:"identity"`
	}
	onlineMeeting struct {
		ID            string `json:"id"`
		Subject       string `json:"subject"`
		StartDateTime string `json:"startDateTime"`
		EndDateTime   string `json:"endDateTime"`
		JoinWebURL    string `json:"joinWebUrl"`
		Participants  *struct {
			Organizer *meetingParticipant  `json:"organizer"`
			Attendees []meetingParticipant `json:"attendees"`
		} `json:"participants"`
	}
	transcript struct {
		ID              string `json:"id"`
		CreatedDateTime string `json:"createdDateTime"`
	}
)

// parseGraphTime reads Graph's timestamps: RFC 3339 with up to seven
// fractional digits, with or without a zone (a calendar time in UTC by the
// Prefer header carries none).
func parseGraphTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.9999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func person(r *recipient) *meet.Person {
	if r == nil || (r.EmailAddress.Address == "" && r.EmailAddress.Name == "") {
		return nil
	}
	return &meet.Person{Name: r.EmailAddress.Name, Address: strings.ToLower(r.EmailAddress.Address)}
}

func joinURL(ev event) string {
	if ev.OnlineMeeting != nil && ev.OnlineMeeting.JoinURL != "" {
		return ev.OnlineMeeting.JoinURL
	}
	return ev.OnlineMeetingURL
}

// Meetings lists the holder's past Teams meetings in the window from the
// calendar, newest first, each with whether a transcript exists.
func (d *Driver) Meetings(ctx context.Context, from, to time.Time) ([]meet.Meeting, error) {
	now := d.now()
	if to.After(now) {
		to = now
	}
	if !to.After(from) {
		return nil, nil
	}
	q := url.Values{}
	q.Set("startDateTime", from.UTC().Format(time.RFC3339))
	q.Set("endDateTime", to.UTC().Format(time.RFC3339))
	q.Set("$select", "id,subject,start,end,organizer,attendees,isOnlineMeeting,onlineMeeting,onlineMeetingUrl")
	q.Set("$orderby", "start/dateTime desc")
	q.Set("$top", "100")
	next := d.base + "/me/calendarView?" + q.Encode()

	var out []meet.Meeting
	seen := map[string]bool{}
	for page := 0; next != "" && page < maxPages; page++ {
		var body struct {
			Value    []event `json:"value"`
			NextLink string  `json:"@odata.nextLink"`
		}
		if err := d.get(ctx, next, &body); err != nil {
			return nil, err
		}
		for _, ev := range body.Value {
			link := joinURL(ev)
			if link == "" {
				continue
			}
			end := parseGraphTime(ev.End.DateTime)
			if !end.IsZero() && end.After(now) {
				continue // still to come, or still running: no transcript yet
			}
			om, err := d.meetingByJoinURL(ctx, link)
			if err != nil {
				if errors.Is(err, meet.ErrLogin) {
					return nil, err
				}
				// A meeting the holder cannot resolve (someone else's tenant,
				// a link Graph will not look up) is listed by the calendar
				// alone, with no transcript.
				m := d.fromEvent(ev, onlineMeeting{ID: "event:" + ev.ID})
				if !seen[m.ID] {
					seen[m.ID] = true
					out = append(out, m)
				}
				continue
			}
			if seen[om.ID] {
				continue
			}
			seen[om.ID] = true
			m := d.fromEvent(ev, om)
			if latest, err := d.latestTranscript(ctx, om.ID); err == nil && latest.ID != "" {
				m.HasTranscript = true
				m.TranscriptAt = parseGraphTime(latest.CreatedDateTime)
				if m.TranscriptAt.IsZero() {
					m.TranscriptAt = m.End
				}
			} else if err != nil && errors.Is(err, meet.ErrLogin) {
				return nil, err
			}
			out = append(out, m)
		}
		next = body.NextLink
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.After(out[j].Start) })
	return out, nil
}

// fromEvent builds the agent's view from the calendar event and, where
// resolved, the online meeting.
func (d *Driver) fromEvent(ev event, om onlineMeeting) meet.Meeting {
	m := meet.Meeting{
		ID:       om.ID,
		Provider: meet.ProviderTeams,
		Title:    strings.TrimSpace(ev.Subject),
		Start:    parseGraphTime(ev.Start.DateTime),
		End:      parseGraphTime(ev.End.DateTime),
	}
	if m.Title == "" {
		m.Title = strings.TrimSpace(om.Subject)
	}
	if m.Start.IsZero() {
		m.Start = parseGraphTime(om.StartDateTime)
	}
	if m.End.IsZero() {
		m.End = parseGraphTime(om.EndDateTime)
	}
	m.Organiser = person(ev.Organizer)
	for _, a := range ev.Attendees {
		if p := person(&a); p != nil {
			m.Participants = append(m.Participants, *p)
		}
	}
	return m
}

// fromOnlineMeeting builds the view from the online meeting alone, for a
// transcript read by id.
func fromOnlineMeeting(om onlineMeeting) meet.Meeting {
	m := meet.Meeting{
		ID:       om.ID,
		Provider: meet.ProviderTeams,
		Title:    strings.TrimSpace(om.Subject),
		Start:    parseGraphTime(om.StartDateTime),
		End:      parseGraphTime(om.EndDateTime),
	}
	if om.Participants != nil {
		if o := om.Participants.Organizer; o != nil {
			m.Organiser = participant(*o)
		}
		for _, a := range om.Participants.Attendees {
			if p := participant(a); p != nil {
				m.Participants = append(m.Participants, *p)
			}
		}
	}
	return m
}

func participant(p meetingParticipant) *meet.Person {
	out := &meet.Person{Address: strings.ToLower(p.UPN)}
	if p.Identity.User != nil {
		out.Name = p.Identity.User.DisplayName
	}
	if out.Name == "" && out.Address == "" {
		return nil
	}
	return out
}

// meetingByJoinURL resolves the online meeting an event's join link names.
func (d *Driver) meetingByJoinURL(ctx context.Context, link string) (onlineMeeting, error) {
	filter := "JoinWebUrl eq '" + strings.ReplaceAll(link, "'", "''") + "'"
	var body struct {
		Value []onlineMeeting `json:"value"`
	}
	if err := d.get(ctx, d.base+"/me/onlineMeetings?$filter="+url.QueryEscape(filter), &body); err != nil {
		return onlineMeeting{}, err
	}
	if len(body.Value) == 0 {
		return onlineMeeting{}, meet.ErrNotFound
	}
	return body.Value[0], nil
}

// latestTranscript is the newest transcript of an online meeting, or an
// empty one when there is none.
func (d *Driver) latestTranscript(ctx context.Context, meetingID string) (transcript, error) {
	var body struct {
		Value []transcript `json:"value"`
	}
	if err := d.get(ctx, d.base+"/me/onlineMeetings/"+url.PathEscape(meetingID)+"/transcripts", &body); err != nil {
		return transcript{}, err
	}
	var latest transcript
	for _, t := range body.Value {
		if latest.ID == "" || parseGraphTime(t.CreatedDateTime).After(parseGraphTime(latest.CreatedDateTime)) {
			latest = t
		}
	}
	return latest, nil
}

// Transcript reads the online meeting, finds its newest transcript and
// downloads it as WebVTT.
func (d *Driver) Transcript(ctx context.Context, meetingID string) (meet.Transcript, error) {
	meetingID = strings.TrimSpace(meetingID)
	if meetingID == "" || strings.HasPrefix(meetingID, "event:") {
		// A calendar-only id was listed with no transcript; there is
		// nothing to read.
		return meet.Transcript{}, meet.ErrNoTranscript
	}
	var om onlineMeeting
	if err := d.get(ctx, d.base+"/me/onlineMeetings/"+url.PathEscape(meetingID), &om); err != nil {
		return meet.Transcript{}, err
	}
	latest, err := d.latestTranscript(ctx, meetingID)
	if err != nil {
		return meet.Transcript{}, err
	}
	if latest.ID == "" {
		return meet.Transcript{}, meet.ErrNoTranscript
	}
	m := fromOnlineMeeting(om)
	m.HasTranscript = true
	m.TranscriptAt = parseGraphTime(latest.CreatedDateTime)
	res, err := d.request(ctx, d.base+"/me/onlineMeetings/"+url.PathEscape(meetingID)+"/transcripts/"+url.PathEscape(latest.ID)+"/content?$format=text/vtt", "text/vtt")
	if err != nil {
		return meet.Transcript{}, err
	}
	defer res.Body.Close()
	if err := status(res); err != nil {
		return meet.Transcript{}, err
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxTranscript))
	if err != nil {
		return meet.Transcript{}, err
	}
	return meet.Transcript{Meeting: m, VTT: body}, nil
}
