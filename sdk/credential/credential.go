// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package credential holds each holder's credential for as long as the
// connector's process lives, and nowhere else.
//
// The design decision (2026-09-17) is that a connector keeps NOTHING at rest.
// The credential is at rest only on the holder's own device: their wallet
// keeps the answers it sent with the approval and sends them again on the
// next ask. Here it exists only in the memory of the attested process, and it
// is gone the moment the process is. There is no sealing key, no volume and
// no storage peer, so there is nothing to withdraw, rotate or clean up, and
// no second approval to obtain before the first.
//
// The price is accepted: a restart forgets every credential. Each holder then
// gets one request on their phone at the next use, and their unattended runs
// wait until they answer it.
//
// The store is generic over the credential's shape, because that is the one
// thing that differs between connectors: a mailbox is a host, a user and a
// password, a calendar may be a refresh token. What does not differ is the
// rule above, so the rule lives here and the shape lives with the connector.
package credential

import (
	"context"
	"errors"
	"sync"
)

// ErrNone means this holder's credential is not in memory: they have never
// connected here, or this process has restarted since.
var ErrNone = errors.New("no credential in memory for this user")

// Store keeps one credential per subject.
//
// The subject is the platform's identity for the acting user, asserted by the
// attested relay. It is never taken from a request body: an app that could
// name its own subject could read anyone's data.
type Store[T any] interface {
	Get(ctx context.Context, sub string) (T, error)
	Put(ctx context.Context, sub string, cred T) error
	Delete(ctx context.Context, sub string) error
	// Close forgets every credential. The store stays usable afterwards, so a
	// reconfiguration can forget everyone without replacing it.
	Close() error
}

// Memory is the store: a map, under a lock, in this process.
//
// It is the production backend, not a stand-in for one. Anything more durable
// would be a copy of a holder's credential that outlives their decision to
// have the connector hold it, which is exactly what the design forbids.
type Memory[T any] struct {
	mu   sync.Mutex
	subs map[string]T
}

func NewMemory[T any]() *Memory[T] { return &Memory[T]{subs: map[string]T{}} }

func (m *Memory[T]) Get(_ context.Context, sub string) (T, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.subs[sub]
	if !ok {
		var zero T
		return zero, ErrNone
	}
	return a, nil
}

func (m *Memory[T]) Put(_ context.Context, sub string, cred T) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subs[sub] = cred
	return nil
}

func (m *Memory[T]) Delete(_ context.Context, sub string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.subs, sub)
	return nil
}

// Close forgets every credential. Nothing survives it, which is the point.
func (m *Memory[T]) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subs = map[string]T{}
	return nil
}
