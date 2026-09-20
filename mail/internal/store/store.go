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

// Account is one connected mailbox.
//
// Secret is the only field that is a credential, and it is never returned by
// any API surface: the connector reads it to dial and nothing else. Everything
// else here exists so a user can be shown what they connected.
type Account struct {
	Provider string    `json:"provider"` // "imap", later "graph", "gmail"
	Host     string    `json:"host"`
	User     string    `json:"user"`
	Secret   string    `json:"secret"`
	LinkedAt time.Time `json:"linked_at"`

	// OwnDomains lets the agent tell colleagues from customers. Supplied by
	// the user at connect time rather than guessed.
	OwnDomains []string `json:"own_domains,omitempty"`
}

// Redacted is the account as anything outside this package may see it.
func (a Account) Redacted() Account {
	a.Secret = ""
	return a
}

// Store keeps one account per subject.
type Store = credential.Store[Account]

// Memory is the in-process store, and the only one.
type Memory = credential.Memory[Account]

func NewMemory() *Memory { return credential.NewMemory[Account]() }
