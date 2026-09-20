// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package credential

import (
	"context"
	"errors"
	"testing"
)

// account stands in for whatever shape a connector keeps.
type account struct {
	User   string
	Secret string
}

func TestMemoryKeepsOneCredentialPerSubject(t *testing.T) {
	m := NewMemory[account]()
	ctx := context.Background()

	if _, err := m.Get(ctx, "user-1"); !errors.Is(err, ErrNone) {
		t.Fatalf("an unknown subject is ErrNone, got %v", err)
	}
	if err := m.Put(ctx, "user-1", account{User: "a@example.com", Secret: "pw-1"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Put(ctx, "user-2", account{User: "b@example.com", Secret: "pw-2"}); err != nil {
		t.Fatal(err)
	}
	a, err := m.Get(ctx, "user-1")
	if err != nil || a.User != "a@example.com" || a.Secret != "pw-1" {
		t.Fatalf("user-1 came back as %+v, %v", a, err)
	}
	// Connecting again replaces: there is one credential per holder here.
	_ = m.Put(ctx, "user-1", account{User: "c@example.com", Secret: "pw-3"})
	if a, _ := m.Get(ctx, "user-1"); a.User != "c@example.com" {
		t.Fatalf("a second Put should replace, got %+v", a)
	}
	if a, _ := m.Get(ctx, "user-2"); a.User != "b@example.com" {
		t.Fatalf("another subject was touched: %+v", a)
	}
}

func TestMemoryDeleteForgetsOnlyThatSubject(t *testing.T) {
	m := NewMemory[account]()
	ctx := context.Background()
	_ = m.Put(ctx, "user-1", account{User: "a@example.com"})
	_ = m.Put(ctx, "user-2", account{User: "b@example.com"})

	if err := m.Delete(ctx, "user-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, "user-1"); !errors.Is(err, ErrNone) {
		t.Fatalf("deleted subject still present: %v", err)
	}
	if _, err := m.Get(ctx, "user-2"); err != nil {
		t.Fatalf("the other subject went with it: %v", err)
	}
	// Deleting what is not there is not an error: the outcome is the same.
	if err := m.Delete(ctx, "nobody"); err != nil {
		t.Fatalf("delete of an unknown subject: %v", err)
	}
}

// A fresh store is what a restart leaves: nothing. The design accepts that and
// the test pins it, so nobody adds a file behind it without noticing. The
// store stays usable after Close, because a reconfiguration forgets everyone
// through it and keeps serving.
func TestMemoryCloseForgetsEverythingAndStaysUsable(t *testing.T) {
	m := NewMemory[account]()
	ctx := context.Background()
	_ = m.Put(ctx, "user-1", account{User: "a@example.com", Secret: "pw"})
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, "user-1"); !errors.Is(err, ErrNone) {
		t.Fatalf("a credential survived Close: %v", err)
	}
	if err := m.Put(ctx, "user-1", account{User: "a@example.com"}); err != nil {
		t.Fatalf("the store must stay usable after Close: %v", err)
	}
}
