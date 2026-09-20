// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package meet is the connector's domain: what a meeting and its transcript
// look like to an attested agent, and what a driver must implement to
// provide them.
//
// The surface is small on purpose. An agent needs to know which past
// meetings the holder took part in have a transcript, read one, and keep
// one. It does not need to join anything, start anything, or record anyone:
// there is no method for any of that on the Driver interface, so the line
// "we do not join and we do not record" is a property of the shape of the
// code, exactly as the mail driver's absence of Send is.
//
// The provider produced the transcript. This connector reads what is there
// for a holder who was in the room, from the holder's own account.
package meet

import (
	"context"
	"errors"
	"time"
)

// Kind is the one capability this connector issues. The vocabulary is closed
// on the wallet side too, and both ends must agree or the holder is shown a
// sentence that does not match what is enforced.
const Kind = "meeting.transcripts"

// MaxWindow bounds a listing: a listing of recordings is paged by the
// provider a month at a time, and there is no reason to scan years.
const MaxWindow = 62 * 24 * time.Hour

// Providers, as the setup step names them and as an account records them.
const (
	ProviderZoom  = "zoom"
	ProviderTeams = "teams"
)

var (
	// ErrNotFound is a meeting the provider does not have, or one the
	// holder cannot see.
	ErrNotFound = errors.New("meeting not found")
	// ErrNoTranscript is a meeting the provider has, with no transcript
	// for it: it was not recorded, or transcription was off, or the
	// provider has not finished producing it.
	ErrNoTranscript = errors.New("this meeting has no transcript")
	// ErrLogin is the provider no longer accepting the holder's sign-in.
	ErrLogin = errors.New("the provider refused the sign-in")
)

// Person is someone in a meeting: a name, an address where the provider
// gives one.
type Person struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
}

// Meeting is one past meeting as the agent sees it.
type Meeting struct {
	ID       string    `json:"id"`
	Provider string    `json:"provider"`
	Title    string    `json:"title"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end,omitempty"`

	Organiser    *Person  `json:"organiser,omitempty"`
	Participants []Person `json:"participants,omitempty"`

	// HasTranscript says the provider holds a transcript the holder can
	// read. TranscriptAt is when it became available, which is what the
	// change feed's cursor moves on.
	HasTranscript bool      `json:"has_transcript"`
	TranscriptAt  time.Time `json:"transcript_at,omitempty"`
	// HasRecording says a recording exists whether or not a transcript
	// does; a meeting whose transcription is still running looks like this.
	HasRecording bool `json:"has_recording,omitempty"`
}

// Transcript is the provider's transcript for one meeting, as WebVTT.
type Transcript struct {
	Meeting Meeting
	VTT     []byte
}

// Profile is the account the credential signs in as.
type Profile struct {
	Address string
	Name    string
}

// Driver is one meeting provider.
//
// There is deliberately no method to join, start, schedule, invite or
// record. The absence is what enforces it.
type Driver interface {
	// Meetings lists the holder's past meetings in [from, to) that have a
	// recording or a transcript, newest first.
	Meetings(ctx context.Context, from, to time.Time) ([]Meeting, error)

	// Transcript returns the transcript of one meeting, as the provider
	// produced it.
	Transcript(ctx context.Context, meetingID string) (Transcript, error)

	Close() error
}
