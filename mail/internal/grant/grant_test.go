// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package grant

import (
	"context"
	"errors"
	"testing"
	"time"
)

func validRequest() Request {
	return Request{
		Nonce:        "n-1",
		SubjectAppID: "590ebdc31b63401fbbb822d5f3886c5e",
		Kind:         Kind,
		Permissions:  []string{"read", "write"},
		ExpiresUnix:  time.Now().Add(90 * 24 * time.Hour).Unix(),
		Req:          map[string]any{"label": "Inbox"},
	}
}

// The check that stops an app aiming a capability at someone else's mail while
// the approval screen still reads truthfully.
func TestRequestMayNotNameTheHolder(t *testing.T) {
	for _, field := range []string{"user", "sub", "account", "mailbox", "tenant", "owner", "email", "address"} {
		r := validRequest()
		r.Req = map[string]any{field: "someone-else@example.com"}
		if _, _, err := r.Validate(time.Now()); !errors.Is(err, ErrBadInput) {
			t.Errorf("a request naming %q should be refused, got %v", field, err)
		}
	}
}

func TestRequestValidation(t *testing.T) {
	now := time.Now()
	cases := map[string]func(*Request){
		"no nonce":        func(r *Request) { r.Nonce = "" },
		"wrong kind":      func(r *Request) { r.Kind = "storage.folder" },
		"short app id":    func(r *Request) { r.SubjectAppID = "abc" },
		"non-hex app id":  func(r *Request) { r.SubjectAppID = "zzzebdc31b63401fbbb822d5f3886c5e" },
		"no permissions":  func(r *Request) { r.Permissions = nil },
		"unknown perm":    func(r *Request) { r.Permissions = []string{"send"} },
		"no expiry":       func(r *Request) { r.ExpiresUnix = 0 },
		"expired already": func(r *Request) { r.ExpiresUnix = now.Add(-time.Hour).Unix() },
		"absurd expiry":   func(r *Request) { r.ExpiresUnix = now.AddDate(5, 0, 0).Unix() },
	}
	for name, mangle := range cases {
		r := validRequest()
		mangle(&r)
		if _, _, err := r.Validate(now); err == nil {
			t.Errorf("%s should have been refused", name)
		}
	}
	if _, _, err := validRequest().Validate(now); err != nil {
		t.Errorf("a valid request was refused: %v", err)
	}
}

// "send" must never be mintable: the absence of the capability is what makes
// "it cannot send" true, rather than a promise in the code.
func TestSendIsNotAPermission(t *testing.T) {
	if _, err := ParsePermissions([]string{"read", "send"}); err == nil {
		t.Fatal("send was accepted as a permission")
	}
}

// Refusing an unknown permission rather than dropping it: minting something
// narrower than the holder was shown is its own kind of lie.
func TestUnknownPermissionIsRefusedNotDropped(t *testing.T) {
	got, err := ParsePermissions([]string{"read", "delete"})
	if err == nil {
		t.Fatalf("expected a refusal, got %v", got)
	}
}

func TestNormaliseSubject(t *testing.T) {
	want := "app:590ebdc31b63401fbbb822d5f3886c5e"
	for _, in := range []string{
		"590ebdc31b63401fbbb822d5f3886c5e",
		"app:590ebdc31b63401fbbb822d5f3886c5e",
		"590EBDC31B63401FBBB822D5F3886C5E",
		"590ebdc3-1b63-401f-bbb8-22d5f3886c5e",
	} {
		got, err := NormaliseSubject(in)
		if err != nil || got != want {
			t.Errorf("NormaliseSubject(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "app:", "not-hex-at-all-not-hex-at-all-xx", "590ebdc3"} {
		if _, err := NormaliseSubject(bad); err == nil {
			t.Errorf("NormaliseSubject(%q) should have failed", bad)
		}
	}
}

func TestMintFindRevoke(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	subject, perms, err := validRequest().Validate(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	g, err := m.Mint(ctx, "user-1", Grant{
		Subject: subject, Permissions: perms,
		ExpiresAt: time.Now().Add(time.Hour), AppName: "Harness",
	})
	if err != nil {
		t.Fatal(err)
	}

	found, err := m.Find(ctx, "user-1", subject)
	if err != nil || found.ID != g.ID {
		t.Fatalf("Find after Mint: %v %+v", err, found)
	}
	if !found.Allows(Read) || !found.Allows(Write) {
		t.Errorf("permissions lost: %v", found.Permissions)
	}

	// Another holder must not see it. This is the whole point of the store.
	if _, err := m.Find(ctx, "user-2", subject); !errors.Is(err, ErrNoGrant) {
		t.Errorf("another user found the grant: %v", err)
	}
	// Another app must not use it.
	other, _ := NormaliseSubject("00000000000000000000000000000001")
	if _, err := m.Find(ctx, "user-1", other); !errors.Is(err, ErrNoGrant) {
		t.Errorf("another app found the grant: %v", err)
	}

	if err := m.Revoke(ctx, "user-1", g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Find(ctx, "user-1", subject); !errors.Is(err, ErrNoGrant) {
		t.Errorf("revoke did not remove access: %v", err)
	}
	if err := m.Revoke(ctx, "user-1", g.ID); !errors.Is(err, ErrNoGrant) {
		t.Errorf("revoking twice should report nothing to revoke, got %v", err)
	}
}

func TestExpiredGrantIsNotUsable(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	subject, _, _ := validRequest().Validate(time.Now())
	if _, err := m.Mint(ctx, "user-1", Grant{
		Subject: subject, Permissions: []Permission{Read},
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Find(ctx, "user-1", subject); !errors.Is(err, ErrExpired) {
		t.Errorf("an expired grant should be refused as expired, got %v", err)
	}
}

// Re-approving replaces, so the holder's list stays readable and one revoke
// actually removes the access rather than one of several copies.
func TestReapprovalReplaces(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	subject, _, _ := validRequest().Validate(time.Now())
	for i := 0; i < 3; i++ {
		if _, err := m.Mint(ctx, "user-1", Grant{
			Subject: subject, Permissions: []Permission{Read},
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := m.List(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("re-approval accumulated %d grants, want 1", len(list))
	}
}

func TestListHidesExpired(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	live, _ := NormaliseSubject("00000000000000000000000000000001")
	dead, _ := NormaliseSubject("00000000000000000000000000000002")
	_, _ = m.Mint(ctx, "u", Grant{Subject: live, ExpiresAt: time.Now().Add(time.Hour)})
	_, _ = m.Mint(ctx, "u", Grant{Subject: dead, ExpiresAt: time.Now().Add(-time.Hour)})
	list, _ := m.List(ctx, "u")
	if len(list) != 1 || list[0].Subject != live {
		t.Fatalf("expired grants should not be listed as access: %+v", list)
	}
}
