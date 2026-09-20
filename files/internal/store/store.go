// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package store is the shape of a file-store credential, kept by the sdk's
// in-memory store for as long as this process lives and nowhere else.
//
// There is one mode. The holder signs in with the provider in their
// browser, held by the wallet, and what this service keeps is the token
// set: an access token that lasts an hour, and the refresh token that
// mints the next one. The refresh token is the one thing this service
// needs the wallet to keep for it: the holder never typed it, and without
// it the credential would not outlive one access token.
package store

import (
	"time"

	"github.com/Privasys/connectors/sdk/credential"
)

// ErrNoAccount means this holder's credential is not in memory.
var ErrNoAccount = credential.ErrNone

// Account is one connected file-store account.
//
// RefreshToken and AccessToken are the credential and are never returned by
// any API surface: the connector reads them to dial and nothing else.
// Everything else exists so a holder can be shown what they connected.
type Account struct {
	// Provider is cloud.ProviderMicrosoft or cloud.ProviderGoogle.
	Provider string `json:"provider"`
	User     string `json:"user"`
	Name     string `json:"name,omitempty"`
	// DriveID is the personal drive, where the connector's folder lives,
	// and DriveType the provider's word for it.
	DriveID   string    `json:"drive_id,omitempty"`
	DriveType string    `json:"drive_type,omitempty"`
	LinkedAt  time.Time `json:"linked_at"`

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
