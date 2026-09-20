// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package store is the shape of a mailbox credential, kept by the sdk's
// in-memory store for as long as this process lives and nowhere else.
//
// The rule (2026-09-17) is the sdk's: the connector keeps NOTHING at rest.
// What is the mail connector's is the shape below, and the promise that
// Secret never leaves this process by any surface.
package store

import (
	"time"

	"github.com/Privasys/connectors/sdk/credential"
)

// ErrNoAccount means this holder's credential is not in memory: they have
// never connected a mailbox here, or this process has restarted since.
var ErrNoAccount = credential.ErrNone

// Provider names how the mailbox is entered. The protocol is IMAP in every
// case; what differs is the credential.
const (
	ProviderIMAP      = "imap"      // an app password the holder typed, sent with LOGIN
	ProviderGoogle    = "google"    // a Google sign-in: an OAuth bearer over XOAUTH2, refreshed from the kept token
	ProviderMicrosoft = "microsoft" // a Microsoft sign-in, the same way
)

// Account is one connected mailbox.
//
// Secret, RefreshToken and AccessToken are the credential and are never
// returned by any API surface: the connector reads them to dial and nothing
// else. Everything else here exists so a user can be shown what they
// connected.
type Account struct {
	Provider string    `json:"provider"`
	Host     string    `json:"host"`
	User     string    `json:"user"`
	Secret   string    `json:"secret"`
	LinkedAt time.Time `json:"linked_at"`

	// The token set of a sign-in. Never serialised, whatever asks: Redacted
	// is belt and braces. The refresh token is what the wallet keeps for
	// this service; the access token is minted from it here and expires
	// within the hour.
	RefreshToken string    `json:"-"`
	AccessToken  string    `json:"-"`
	Expiry       time.Time `json:"-"`

	// OwnDomains lets the agent tell colleagues from customers. Supplied by
	// the user at connect time rather than guessed.
	OwnDomains []string `json:"own_domains,omitempty"`
}

// SignedIn reports whether the mailbox is entered with a sign-in's token
// set rather than a password.
func (a Account) SignedIn() bool {
	return a.Provider == ProviderGoogle || a.Provider == ProviderMicrosoft
}

// Redacted is the account as anything outside this package may see it.
func (a Account) Redacted() Account {
	a.Secret, a.RefreshToken, a.AccessToken = "", "", ""
	a.Expiry = time.Time{}
	return a
}

// Store keeps one account per subject.
type Store = credential.Store[Account]

// Memory is the in-process store, and the only one.
type Memory = credential.Memory[Account]

func NewMemory() *Memory { return credential.NewMemory[Account]() }
