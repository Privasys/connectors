// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package zoomdrv reads the transcripts Zoom produced for the holder's own
// cloud recordings, through the Zoom API with the holder's OAuth bearer.
//
// Three calls and nothing else: who the account is, the account's
// recordings in a window, and the files of one recording, one of which is
// the transcript. Nothing here can start, join or record a meeting.
package zoomdrv

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

// DefaultAPIBase is Zoom's API.
const DefaultAPIBase = "https://api.zoom.us/v2"

// maxTranscript bounds a download; a transcript is text.
const maxTranscript = 16 << 20

// pageSize is Zoom's maximum for a recordings listing.
const pageSize = 300

// Config is how the driver dials.
type Config struct {
	// APIBase is the API's origin and version prefix; a test points it at a
	// fake. Empty is DefaultAPIBase.
	APIBase string
	// Token mints the bearer for each request, refreshing as needed.
	Token func(ctx context.Context) (string, error)
	// HTTPClient reaches the API and the download URLs; nil is a default.
	HTTPClient *http.Client
}

// Driver is one Zoom account.
type Driver struct {
	base  string
	token func(ctx context.Context) (string, error)
	http  *http.Client
	// downloadHosts is where a recording file may be fetched from with the
	// holder's bearer: Zoom's own domains, and the API's host so a fake can
	// serve its own files. A URL anywhere else is refused rather than sent
	// a bearer.
	downloadHosts []string
}

// Open proves the bearer with one call and returns the driver and the
// account it signs in as.
func Open(ctx context.Context, cfg Config) (*Driver, meet.Profile, error) {
	if cfg.Token == nil {
		return nil, meet.Profile{}, errors.New("zoom: no token source")
	}
	base := strings.TrimRight(cfg.APIBase, "/")
	if base == "" {
		base = DefaultAPIBase
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return nil, meet.Profile{}, fmt.Errorf("zoom: bad API base %q", cfg.APIBase)
	}
	d := &Driver{base: base, token: cfg.Token, http: cfg.HTTPClient, downloadHosts: []string{u.Host, "zoom.us", "zoom.com"}}
	if d.http == nil {
		d.http = &http.Client{Timeout: 60 * time.Second}
	}
	var me struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		FirstName   string `json:"first_name"`
		LastName    string `json:"last_name"`
	}
	if err := d.get(ctx, d.base+"/users/me", &me); err != nil {
		return nil, meet.Profile{}, err
	}
	name := me.DisplayName
	if name == "" {
		name = strings.TrimSpace(me.FirstName + " " + me.LastName)
	}
	return d, meet.Profile{Address: strings.ToLower(me.Email), Name: name}, nil
}

func (d *Driver) Close() error { return nil }

// get performs one authenticated GET and decodes the JSON answer.
func (d *Driver) get(ctx context.Context, u string, out any) error {
	res, err := d.request(ctx, u)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if err := status(res); err != nil {
		return err
	}
	return json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out)
}

func (d *Driver) request(ctx context.Context, u string) (*http.Response, error) {
	tok, err := d.token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json, text/vtt, */*")
	res, err := d.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zoom: %w", err)
	}
	return res, nil
}

// status maps Zoom's refusals: a 401 is the sign-in, a 404 the meeting,
// anything else is the provider's fault.
func status(res *http.Response) error {
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return meet.ErrLogin
	case res.StatusCode == http.StatusNotFound:
		return meet.ErrNotFound
	case res.StatusCode/100 != 2:
		body, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("zoom answered %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// recording is Zoom's shape for one recorded meeting instance.
type recording struct {
	UUID      string `json:"uuid"`
	ID        int64  `json:"id"`
	Topic     string `json:"topic"`
	HostEmail string `json:"host_email"`
	StartTime string `json:"start_time"`
	Duration  int    `json:"duration"` // minutes
	Files     []struct {
		ID             string `json:"id"`
		FileType       string `json:"file_type"`
		FileExtension  string `json:"file_extension"`
		RecordingStart string `json:"recording_start"`
		RecordingEnd   string `json:"recording_end"`
		DownloadURL    string `json:"download_url"`
		Status         string `json:"status"`
		RecordingType  string `json:"recording_type"`
	} `json:"recording_files"`
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// meeting turns a recording into the agent's view, and names the transcript
// file's download URL when there is one.
func meeting(r recording) (meet.Meeting, string) {
	m := meet.Meeting{
		ID:       r.UUID,
		Provider: meet.ProviderZoom,
		Title:    strings.TrimSpace(r.Topic),
		Start:    parseTime(r.StartTime),
	}
	if r.Duration > 0 && !m.Start.IsZero() {
		m.End = m.Start.Add(time.Duration(r.Duration) * time.Minute)
	}
	if r.HostEmail != "" {
		m.Organiser = &meet.Person{Address: strings.ToLower(r.HostEmail)}
	}
	download := ""
	for _, f := range r.Files {
		if f.Status != "" && !strings.EqualFold(f.Status, "completed") {
			continue
		}
		m.HasRecording = true
		if !strings.EqualFold(f.FileType, "TRANSCRIPT") {
			continue
		}
		m.HasTranscript = true
		download = f.DownloadURL
		at := parseTime(f.RecordingEnd)
		if at.IsZero() {
			at = m.End
		}
		if at.After(m.TranscriptAt) {
			m.TranscriptAt = at
		}
	}
	return m, download
}

// Meetings lists the holder's recordings in the window. Zoom pages a month
// at a time, so a longer window is asked for month by month; the answer is
// newest first.
func (d *Driver) Meetings(ctx context.Context, from, to time.Time) ([]meet.Meeting, error) {
	var out []meet.Meeting
	seen := map[string]bool{}
	for chunkFrom := from; chunkFrom.Before(to); {
		chunkTo := chunkFrom.Add(30 * 24 * time.Hour)
		if chunkTo.After(to) {
			chunkTo = to
		}
		next := ""
		for {
			q := url.Values{}
			q.Set("from", chunkFrom.UTC().Format("2006-01-02"))
			q.Set("to", chunkTo.UTC().Format("2006-01-02"))
			q.Set("page_size", fmt.Sprint(pageSize))
			if next != "" {
				q.Set("next_page_token", next)
			}
			var page struct {
				NextPageToken string      `json:"next_page_token"`
				Meetings      []recording `json:"meetings"`
			}
			if err := d.get(ctx, d.base+"/users/me/recordings?"+q.Encode(), &page); err != nil {
				return nil, err
			}
			for _, r := range page.Meetings {
				m, _ := meeting(r)
				if m.ID == "" || seen[m.ID] {
					continue
				}
				// The date window is Zoom's, in days; the caller's is in
				// time, so it is applied once more here.
				if !m.Start.IsZero() && (m.Start.Before(from) || !m.Start.Before(to)) {
					continue
				}
				seen[m.ID] = true
				out = append(out, m)
			}
			if page.NextPageToken == "" {
				break
			}
			next = page.NextPageToken
		}
		chunkFrom = chunkTo
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.After(out[j].Start) })
	return out, nil
}

// Transcript fetches the recording's files and downloads the transcript.
func (d *Driver) Transcript(ctx context.Context, meetingID string) (meet.Transcript, error) {
	meetingID = strings.TrimSpace(meetingID)
	if meetingID == "" {
		return meet.Transcript{}, meet.ErrNotFound
	}
	var r recording
	if err := d.get(ctx, d.base+"/meetings/"+encodeUUID(meetingID)+"/recordings", &r); err != nil {
		return meet.Transcript{}, err
	}
	m, download := meeting(r)
	if download == "" {
		return meet.Transcript{}, meet.ErrNoTranscript
	}
	if !d.allowedDownload(download) {
		return meet.Transcript{}, fmt.Errorf("zoom named a download host this connector will not send a bearer to: %s", download)
	}
	res, err := d.request(ctx, download)
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

// allowedDownload holds a download URL to Zoom's own hosts (or the API's,
// for a fake). The bearer is the holder's credential, and a URL in an API
// answer is data, not somewhere to send it.
func (d *Driver) allowedDownload(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Host)
	// Plain http only to the API's own host, and only when the API itself
	// is plain http, which is a fake in a test.
	if u.Scheme == "http" {
		return strings.HasPrefix(d.base, "http://") && host == d.downloadHosts[0]
	}
	if u.Scheme != "https" {
		return false
	}
	for _, h := range d.downloadHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// encodeUUID escapes a meeting UUID for the path. Zoom's rule: a UUID that
// begins with a slash or contains a double slash must be encoded twice.
func encodeUUID(id string) string {
	if strings.HasPrefix(id, "/") || strings.Contains(id, "//") {
		return url.PathEscape(url.PathEscape(id))
	}
	return url.PathEscape(id)
}
