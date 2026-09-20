// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package caldavdrv

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Privasys/connectors/calendar/internal/cal"
)

// An event id encodes the calendar, the object's href, the etag it was read
// at, and for an occurrence of a recurring event which one. The etag is the
// point: an id from a listing addresses the version that was listed, so a
// later change makes the id fail (cal.ErrStale) rather than address what the
// event has become. Opaque to the agent, and to the harness.

const idVersion = "1"

type eventRef struct {
	cal      string // the collection path
	href     string // the object path
	etag     string // the version listed
	instance string // RFC 3339 start of the occurrence, "" for a one-off
}

func (r eventRef) id() string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{idVersion, r.cal, r.href, r.etag, r.instance}, "\x00")))
}

func parseID(id string) (eventRef, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(id))
	if err != nil {
		return eventRef{}, fmt.Errorf("%w: %v", cal.ErrBadID, err)
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 5 || parts[0] != idVersion || parts[1] == "" || parts[2] == "" {
		return eventRef{}, cal.ErrBadID
	}
	return eventRef{cal: parts[1], href: parts[2], etag: parts[3], instance: parts[4]}, nil
}

// A calendar id is its collection path, encoded so it reads as a handle
// rather than as a URL to be edited.
func calendarID(path string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(path))
}

func calendarPath(id string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(id))
	if err != nil || len(raw) == 0 || raw[0] != '/' {
		return "", fmt.Errorf("malformed calendar id")
	}
	return string(raw), nil
}
