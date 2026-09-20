// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/connectors/mail/internal/mail"
	"github.com/Privasys/connectors/mail/internal/store"
	"github.com/Privasys/connectors/sdk/grant"
)

// The order of refusals for a holder is credential first, approval second.
//
// After a restart both are gone, and what fixes it is the holder's device
// sending the details it kept, which only request_access WITH ask_again
// makes it do: the device's own record still says approved. An agent told
// "ask the user to approve" would request access plainly, be told it already
// has it, and go round again (seen 2026-09-19). So a holder with no
// credential in memory gets that instruction before anything about
// approvals, and only a holder whose credential is here is told about them.
func TestNoCredentialIsToldToAskTheDeviceNotToApprove(t *testing.T) {
	s := New(fakeStore{subs: map[string]store.Account{}}, grant.NewMemory(), true)
	w := callAs(t, s, "/tools/account", "holder-1", "0123456789abcdef0123456789abcdef", `{}`)
	credentialNeededBody(t, w)
	if strings.Contains(w.Body.String(), "not approved") {
		t.Fatalf("the approval is not the problem yet: %s", w.Body)
	}
}

func TestConnectedHolderWithoutGrantIsToldToApprove(t *testing.T) {
	s := New(fakeStore{subs: map[string]store.Account{"holder-1": {}}}, grant.NewMemory(), true)
	r := httptest.NewRequest("POST", "https://mail-connector.apps.test.privasys.org/tools/account", nil)
	r.Header.Set(PeerAppHeader, "0123456789abcdef0123456789abcdef")
	r.Header.Set(PeerVerifiedHeader, "true")
	err := s.authorise(r, "holder-1", grant.Read)
	if err == nil {
		t.Fatal("a connected holder without a grant must be refused")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not approved") || !strings.Contains(msg, "request_access for their "+mail.Kind) ||
		!strings.Contains(msg, "Never ask for a password yourself") {
		t.Fatalf("a connected holder without a grant is told about the approval, and the password stays out of the chat: %q", msg)
	}
	for _, never := range []string{"http://", "https://", "connect_mailbox", "folder", "Drive"} {
		if strings.Contains(msg, never) {
			t.Fatalf("the refusal must not say %q: %q", never, msg)
		}
	}
}

// An expired approval is renewed on the device, and the refusal says so
// without sending anyone to a page.
func TestExpiredGrantIsToldToRenew(t *testing.T) {
	s := New(fakeStore{subs: map[string]store.Account{"holder-1": {}}}, grant.NewMemory(), true)
	// The memory store keeps an expired grant until it is found: mint one
	// already past its expiry.
	_, _ = s.grantStore().Mint(context.Background(), "holder-1", grant.Grant{
		Subject:     "app:0123456789abcdef0123456789abcdef",
		Permissions: []grant.Permission{grant.Read},
	})
	r := httptest.NewRequest("POST", "/tools/account", nil)
	r.Header.Set(PeerAppHeader, "0123456789abcdef0123456789abcdef")
	err := s.authorise(r, "holder-1", grant.Read)
	if err == nil || !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "request_access") {
		t.Fatalf("an expired approval is renewed on the device: %v", err)
	}
	if strings.Contains(err.Error(), "http") {
		t.Fatalf("no page: %v", err)
	}
}
