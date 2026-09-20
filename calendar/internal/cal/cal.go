// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package cal is the connector's domain: what a calendar looks like to an
// attested agent, and what a driver must implement to provide one.
//
// The surface is deliberately smaller than CalDAV. An agent needs to see what
// is on the holder's calendar in a bounded window, read one event, look
// something up, know when the holder is busy, and leave a tentative event for
// the holder to confirm. It does not need to invite anyone, answer an
// invitation, or touch an event it did not create, and every capability left
// out is one a description cannot talk the model into using.
//
// The provider is the system of record. This connector reads on demand and
// stores nothing.
package cal

import (
	"context"
	"errors"
	"time"
)

// Kind is the one capability this connector issues. The vocabulary is closed
// on the wallet side too, and both ends must agree or the holder is shown a
// sentence that does not match what is enforced.
const Kind = "calendar.events"

// ProposedProp marks an event this connector created, as a tentative
// proposal for the holder. Only an event carrying it may be updated or
// deleted here: the connector never touches an event it did not create.
const ProposedProp = "X-PRIVASYS-PROPOSED"

// MaxWindow bounds a listing: a calendar holds years, and there is no way to
// list them all.
const MaxWindow = 62 * 24 * time.Hour

var (
	// ErrNotFound is an event the calendar does not have. Distinct from an
	// error, because an event disappearing between a listing and a read is
	// ordinary in a live calendar, not a fault.
	ErrNotFound = errors.New("event not found")
	// ErrStale is an id whose event changed since it was listed. The id
	// encodes the version it was read at, so a stale one fails rather than
	// addressing what the event has become.
	ErrStale = errors.New("the event has changed since it was listed; list again for a fresh id")
	// ErrNotProposed is an attempt to change an event this connector did not
	// create.
	ErrNotProposed = errors.New("this event was not proposed by the assistant, so it will not be changed or deleted here; only the holder can, in their own calendar")
	// ErrBadID is an id that does not decode.
	ErrBadID = errors.New("malformed event id")
)

// Calendar is one collection the holder can see.
type Calendar struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Primary is the calendar a proposal lands on when none is named: the
	// holder's own, as far as the provider lets it be told.
	Primary  bool `json:"primary"`
	ReadOnly bool `json:"read_only,omitempty"`
}

// Attendee is one participant. Status is the provider's word: "accepted",
// "declined", "tentative" or "needs-action".
type Attendee struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
	Status  string `json:"status,omitempty"`
}

// Event is one occurrence as the agent sees it. A recurring event appears
// once per occurrence in the window, each with its own id.
type Event struct {
	ID       string    `json:"id"`
	Calendar string    `json:"calendar"`
	Title    string    `json:"title"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	AllDay   bool      `json:"all_day"`
	Location string    `json:"location,omitempty"`

	Attendees []Attendee `json:"attendees,omitempty"`
	Organiser *Attendee  `json:"organiser,omitempty"`

	// Description is the sender's own words, with any credentials stripped
	// by the connector before the text reaches the agent (package redact).
	Description string `json:"description,omitempty"`
	Redactions  int    `json:"redactions,omitempty"`

	ConferenceLink string `json:"conference_link,omitempty"`
	// Recurrence is a sentence about the rule, "every week on Monday", empty
	// for a one-off.
	Recurrence string `json:"recurrence,omitempty"`
	// Host says the holder organised it, or it is their own event with no
	// organiser at all.
	Host   bool   `json:"host"`
	Status string `json:"status,omitempty"`
	// Free says the event shows the holder as available (TRANSP:TRANSPARENT):
	// a birthday, a reminder. Not busy time.
	Free bool `json:"free,omitempty"`

	// Proposed is set on an event this connector created, with the run id
	// it was created for.
	Proposed   bool   `json:"proposed,omitempty"`
	ProposedBy string `json:"proposed_by,omitempty"`
}

// Proposal is a tentative event the agent leaves for the holder. Attendees
// are names and addresses for the DESCRIPTION text, never ATTENDEE
// properties: no server sends an invitation for a proposal.
type Proposal struct {
	Title       string
	Description string
	Location    string
	Start, End  time.Time
	AllDay      bool
	Attendees   []string
	// Ref is the run id, or a random id, recorded on the event.
	Ref string
}

// Patch changes a proposed event. A nil field is left alone.
type Patch struct {
	Title       *string
	Description *string
	Location    *string
	Start, End  *time.Time
	Attendees   []string
}

// Busy is one interval the holder is not free.
type Busy struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Change is one event from the calendar's own feed. Kind is "changed"
// (created or updated: CalDAV does not tell them apart), "removed", or
// "calendar_changed" for a server that can only say that something in the
// calendar changed, in which case ID is empty and the agent lists again.
type Change struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Calendar string `json:"calendar,omitempty"`
}

// Driver is one calendar provider. CalDAV covers Google (with a bearer),
// iCloud, Fastmail, Nextcloud and any RFC 4791 server (with an app password).
//
// There is deliberately no method to accept, decline or invite, and none to
// change an event the connector did not create: the absence is what enforces
// it, as the mail driver's absence of Send does.
type Driver interface {
	Calendars(ctx context.Context) ([]Calendar, error)

	// Events returns the occurrences in [from, to) on one calendar, or on
	// all when calendar is empty, soonest first.
	Events(ctx context.Context, calendar string, from, to time.Time) ([]Event, error)

	Get(ctx context.Context, id string) (Event, error)

	// Propose creates a TENTATIVE event with no attendees on the calendar,
	// or on the primary one when calendar is empty.
	Propose(ctx context.Context, calendar string, p Proposal) (Event, error)

	// Update and Delete refuse any event that does not carry ProposedProp.
	Update(ctx context.Context, id string, p Patch) (Event, error)
	Delete(ctx context.Context, id string) error

	// Changes reports what changed since the cursor, holding for up to wait
	// when nothing has. The cursor is opaque.
	Changes(ctx context.Context, since string, wait time.Duration) ([]Change, string, error)

	Close() error
}
