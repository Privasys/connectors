// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package store is the shape of a calendar credential, kept by the sdk's
// in-memory store for as long as this process lives and nowhere else.
//
// Two modes. An app password, which the holder typed and their device keeps,
// so nothing is asked of the wallet beyond sending it again. Or a Google
// sign-in, where the refresh token is the one thing this service needs the
// wallet to keep for it: the holder never typed it, and without it the
// credential would not outlive one access token.
package store

import (
	"time"

	"github.com/Privasys/connectors/sdk/credential"
)

// ErrNoAccount means this holder's credential is not in memory.
var ErrNoAccount = credential.ErrNone

// Provider names the credential mode.
const (
	ProviderCalDAV = "caldav" // basic auth with an app password
	ProviderGoogle = "google" // an OAuth bearer, refreshed from the kept token
)

// Account is one connected calendar account.
//
// Secret, RefreshToken and AccessToken are the credential and are never
// returned by any API surface: the connector reads them to dial and nothing
// else. Everything else exists so a holder can be shown what they connected.
type Account struct {
	Provider string `json:"provider"`
	// Endpoint is the CalDAV context URL the account was proved against.
	Endpoint string `json:"endpoint"`
	// Principal is the principal path when the provider does not discover
	// it (Google), empty otherwise.
	Principal string    `json:"principal,omitempty"`
	User      string    `json:"user"`
	Secret    string    `json:"-"`
	LinkedAt  time.Time `json:"linked_at"`

	// Never serialised, whatever asks: Redacted is belt and braces.
	RefreshToken string    `json:"-"`
	AccessToken  string    `json:"-"`
	Expiry       time.Time `json:"-"`
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
