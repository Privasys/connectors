// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package store is the shape of a meetings credential, kept by the sdk's
// in-memory store for as long as this process lives and nowhere else.
//
// One mode only: an OAuth sign-in, at Zoom or at Microsoft. The refresh
// token is the one thing this service needs the wallet to keep for it: the
// holder never typed it, and without it the credential would not outlive
// one access token.
package store

import (
	"time"

	"github.com/Privasys/connectors/sdk/credential"
)

// ErrNoAccount means this holder's credential is not in memory.
var ErrNoAccount = credential.ErrNone

// Account is one connected meetings account.
//
// RefreshToken and AccessToken are the credential and are never returned by
// any API surface: the connector reads them to dial and nothing else.
// Everything else exists so a holder can be shown what they connected.
type Account struct {
	// Provider is meet.ProviderZoom or meet.ProviderTeams.
	Provider string `json:"provider"`
	// User is the address the account signed in as, and Name what the
	// provider calls it.
	User     string    `json:"user"`
	Name     string    `json:"name,omitempty"`
	LinkedAt time.Time `json:"linked_at"`

	// Never serialised, whatever asks: Redacted is belt and braces.
	RefreshToken string    `json:"-"`
	AccessToken  string    `json:"-"`
	Expiry       time.Time `json:"-"`
}

// Redacted is the account as anything outside this package may see it.
func (a Account) Redacted() Account {
	a.RefreshToken, a.AccessToken = "", ""
	a.Expiry = time.Time{}
	return a
}

// Store keeps one account per subject.
type Store = credential.Store[Account]

// Memory is the in-process store, and the only one.
type Memory = credential.Memory[Account]

func NewMemory() *Memory { return credential.NewMemory[Account]() }
