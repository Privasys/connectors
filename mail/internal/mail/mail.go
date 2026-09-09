// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package mail is the connector's domain: what a mailbox looks like to an
// attested agent, and what a driver must implement to provide one.
//
// The surface is deliberately smaller than IMAP or the Gmail API. An agent
// needs to see what arrived, read one message, look something up, label what
// it triaged and leave a reply for the user to send. It does not need folder
// management, flags in general, or the ability to send, and every capability
// left out is one that cannot be misused by a message that talks the model
// into something.
package mail

import (
	"context"
	"errors"
	"time"
)

// Permission mirrors the wallet's closed vocabulary. A driver call site checks
// it before acting, so a grant that says read cannot label or draft.
type Permission string

const (
	PermRead  Permission = "read"
	PermWrite Permission = "write"
)

// ErrNotFound is returned for a message the mailbox does not have. It is
// distinct from an error, because a message disappearing between a listing and
// a read is ordinary in a live mailbox, not a fault.
var ErrNotFound = errors.New("message not found")

// ErrUnreadable is a message the SERVER will not serve. One in 200 of a real
// mailbox is this, so every caller must be able to carry on without it rather
// than failing the run.
var ErrUnreadable = errors.New("message cannot be read from the server")

// Address is one participant. Name is often empty and never trusted for
// identity; Addr is what anything routes on.
type Address struct {
	Name string `json:"name,omitempty"`
	Addr string `json:"addr"`
}

// Header is what a listing returns: enough to triage, without a body.
type Header struct {
	ID        string    `json:"id"`
	ThreadID  string    `json:"thread_id,omitempty"`
	Date      time.Time `json:"date"`
	From      Address   `json:"from"`
	To        []Address `json:"to,omitempty"`
	Cc        []Address `json:"cc,omitempty"`
	Subject   string    `json:"subject"`
	Snippet   string    `json:"snippet,omitempty"`
	Unread    bool      `json:"unread"`
	Labels    []string  `json:"labels,omitempty"`
	HasAttach bool      `json:"has_attachments"`

	// Repliable is false for a sender no human reads: no-reply addresses,
	// mailing-list bounce paths, automated notifications. The triage skill
	// must never draft to one, and the first real draft this connector's
	// spike ever produced was a reply to a Google security alert, which is
	// exactly why this is a field and not a guideline.
	Repliable bool `json:"repliable"`
}

// Message is a header plus the body the agent will actually read.
type Message struct {
	Header

	// Text is the sender's own words: transfer-decoded, charset-converted,
	// with quoted history and the signature block removed, and with secrets
	// redacted (see package redact). It is never the raw MIME.
	Text string `json:"text"`

	// Truncated says the body was longer than the fetch bound. An agent that
	// needs the rest asks for it explicitly rather than being handed a
	// mailbox-sized string by default.
	Truncated bool `json:"truncated,omitempty"`

	// Redactions counts what the secret filter removed. Surfaced so the agent
	// knows a login mail was a login mail rather than seeing a gap.
	Redactions int `json:"redactions,omitempty"`

	Attachments []Attachment `json:"attachments,omitempty"`
}

// Attachment is listed, never fetched by default: pulling a 30 MB file into an
// agent's context is a cost decision, so it takes a separate deliberate call.
type Attachment struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	Part string `json:"part"`
}

// Draft is a reply the user will read and send themselves. There is no Send:
// v1 cannot send, and the absence is enforced by there being no method for it
// rather than by a flag someone can flip.
type Draft struct {
	// ReplyTo is the message being replied to. A draft is always a reply to
	// something the mailbox already holds, never a new message to an address
	// that appeared in some content.
	ReplyTo string    `json:"reply_to"`
	Body    string    `json:"body"`
	CC      []Address `json:"cc,omitempty"`
}

// DraftRef is what a mailbox hands back after storing a draft.
//
// Treat it as advisory. Gmail deletes and re-creates a draft under a new id
// when its own interface touches one, so this is not a durable handle. What
// makes drafting idempotent is the record of which THREAD has been handled,
// kept on the user's own Drive.
type DraftRef struct {
	ID       string `json:"id"`
	ThreadID string `json:"thread_id,omitempty"`
}

// ListOptions bounds a listing. There is no "list everything": the mailboxes
// this runs against hold tens of thousands of messages, so a caller always
// works from a recent window.
type ListOptions struct {
	Folder     string
	Since      time.Time
	Limit      int
	UnreadOnly bool
	Cursor     string
}

// Page is one window of headers plus where to continue.
type Page struct {
	Headers []Header `json:"headers"`
	Cursor  string   `json:"cursor,omitempty"`

	// Unreadable lists ids the server refused. Reported rather than hidden,
	// because a triage run that silently skipped a message the user cares
	// about is worse than one that says it could not read it.
	Unreadable []string `json:"unreadable,omitempty"`
}

// Change is one event from the mailbox's own feed.
type Change struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // "arrived", "removed", "flags"
}

// Driver is one mailbox provider. IMAP first, then Microsoft Graph, then the
// Gmail API, in that order because that is the order of how much permission
// each one needs from its vendor before it can serve a real user.
type Driver interface {
	// List returns headers, newest first.
	List(ctx context.Context, o ListOptions) (Page, error)

	// Get returns one message, decoded and redacted.
	Get(ctx context.Context, id string, maxBytes int) (Message, error)

	// Thread returns the conversation a message belongs to, oldest first.
	Thread(ctx context.Context, id string, maxBytes int) ([]Message, error)

	// Search runs the PROVIDER's own search. Deliberately not ours: providers
	// index years of mail and we hold none of it.
	Search(ctx context.Context, query string, o ListOptions) (Page, error)

	// Sent returns the user's own outbound text, for the style pass. Bodies
	// are stripped to own words and never retained by the connector.
	Sent(ctx context.Context, limit int, since time.Time) ([]Message, error)

	// SetLabels adds and removes labels. On Gmail this is CREATE plus COPY,
	// which is ordinary IMAP that happens to do the Gmail thing, so there is
	// no provider-specific path here.
	SetLabels(ctx context.Context, id string, add, remove []string) error

	MarkRead(ctx context.Context, id string, read bool) error

	// CreateDraft stores a reply in the user's Drafts, threaded, unsent.
	CreateDraft(ctx context.Context, d Draft) (DraftRef, error)
	DeleteDraft(ctx context.Context, id string) error

	// Changes long-polls the provider's own event source: IMAP IDLE, Gmail
	// users.watch, Graph subscriptions. Returns as soon as anything happens
	// or when wait elapses, so a quiet mailbox costs nothing.
	Changes(ctx context.Context, since string, wait time.Duration) ([]Change, string, error)

	Close() error
}
