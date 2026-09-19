// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package store holds each holder's mailbox credential for as long as this
// process lives, and nowhere else.
//
// The design decision (2026-09-17) is that the connector keeps NOTHING at
// rest. The credential is at rest only on the holder's own device: their
// wallet keeps the answers it sent with the approval and sends them again on
// the next ask. Here it exists only in the memory of this attested process,
// and it is gone the moment the process is. There is no sealing key, no
// volume and no storage peer, so there is nothing to withdraw, rotate or
// clean up, and no second approval to obtain before the first.
//
// The price is accepted: a restart forgets every credential. Each holder then
// gets one request on their phone at the next use, and their unattended runs
// wait until they answer it.
//
// The Store interface stays so the rest of the connector is written against
// the seam rather than the map, and so a test can observe what was kept.
package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrNoAccount means this holder's credential is not in memory: they have
// never connected a mailbox here, or this process has restarted since.
var ErrNoAccount = errors.New("no mailbox credential in memory for this user")

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
//
// The subject is the platform's identity for the acting user, asserted by the
// attested relay. It is never taken from a request body: an app that could
// name its own subject could read anyone's mailbox.
type Store interface {
	Get(ctx context.Context, sub string) (Account, error)
	Put(ctx context.Context, sub string, a Account) error
	Delete(ctx context.Context, sub string) error
	Close() error
}

// Memory is the store: a map, under a lock, in this process.
//
// It is the production backend, not a stand-in for one. Anything more durable
// would be a copy of a holder's credential that outlives their decision to
// have this service hold it, which is exactly what the design forbids.
type Memory struct {
	mu   sync.Mutex
	subs map[string]Account
}

func NewMemory() *Memory { return &Memory{subs: map[string]Account{}} }

func (m *Memory) Get(_ context.Context, sub string) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.subs[sub]
	if !ok {
		return Account{}, ErrNoAccount
	}
	return a, nil
}

func (m *Memory) Put(_ context.Context, sub string, a Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subs[sub] = a
	return nil
}

func (m *Memory) Delete(_ context.Context, sub string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.subs, sub)
	return nil
}

// Close forgets every credential. Nothing survives it, which is the point.
func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subs = map[string]Account{}
	return nil
}
