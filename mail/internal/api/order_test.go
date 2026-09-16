// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/connectors/mail/internal/grant"
	"github.com/Privasys/connectors/mail/internal/store"
)

// The order of operations for a holder is link first, approve second. A
// refusal that names the approval before the mailbox exists sends the agent
// to the wallet for nothing (seen on a phone, 2026-09-14: "nothing to
// approve").
func TestUnlinkedHolderIsSentToLinkNotToApprove(t *testing.T) {
	s := New(fakeStore{subs: map[string]store.Account{}}, grant.NewMemory(), true)
	r := httptest.NewRequest("POST", "https://mail-connector.apps.test.privasys.org/tools/account", nil)
	r.Header.Set(PeerAppHeader, "0123456789abcdef0123456789abcdef")
	r.Header.Set(PeerVerifiedHeader, "true")
	err := s.authorise(r, "holder-1", grant.Read)
	if err == nil {
		t.Fatal("an unlinked, unapproved holder must be refused")
	}
	msg := err.Error()
	// Since 2026-09-16 the wallet connects the mailbox on the approval screen
	// (plan §3.7): the refusal sends the agent to request access, keeps the
	// password out of the chat, and names connect_mailbox only as the
	// fallback for an older wallet.
	if !strings.Contains(msg, "not connected") || !strings.Contains(msg, "request access to their "+grant.Kind) ||
		!strings.Contains(msg, "never ask for a password yourself") || !strings.Contains(msg, "connect_mailbox with no arguments") {
		t.Fatalf("the refusal must send the agent to the wallet and keep the password out of the chat: %q", msg)
	}
	if strings.Contains(msg, "Do not request access") {
		t.Fatalf("requesting access is the way in now: %q", msg)
	}
	if !strings.Contains(msg, "https://mail-connector.apps.test.privasys.org/") {
		t.Fatalf("the page stays named for people who prefer it: %q", msg)
	}
}

func TestLinkedHolderWithoutGrantIsToldToApprove(t *testing.T) {
	s := New(fakeStore{subs: map[string]store.Account{"holder-1": {}}}, grant.NewMemory(), true)
	r := httptest.NewRequest("POST", "https://mail-connector.apps.test.privasys.org/tools/account", nil)
	r.Header.Set(PeerAppHeader, "0123456789abcdef0123456789abcdef")
	r.Header.Set(PeerVerifiedHeader, "true")
	err := s.authorise(r, "holder-1", grant.Read)
	if err == nil || !strings.Contains(err.Error(), "request access to their "+grant.Kind) {
		t.Fatalf("a linked holder without a grant is told about the approval: %v", err)
	}
}

// withdrawnStore is a holder whose Drive folder this service can no longer
// read: the runtime still says approved, Drive answers 401.
type withdrawnStore struct{}

func (withdrawnStore) Get(context.Context, string) (store.Account, error) {
	return store.Account{}, fmt.Errorf("%w (drive answered 401 resolving credential.enc)", store.ErrFolderWithdrawn)
}
func (withdrawnStore) Put(context.Context, string, store.Account) error {
	return store.ErrFolderWithdrawn
}
func (withdrawnStore) Delete(context.Context, string) error { return nil }
func (withdrawnStore) Close() error                         { return nil }

// A folder withdrawn in Drive is "nothing connected", whatever the runtime's
// record and the access list say (2026-09-16: the agent read "approved" from
// list_access and told the holder everything was set up).
func TestWithdrawnFolderIsToldToConnectAgain(t *testing.T) {
	s := New(withdrawnStore{}, grant.NewMemory(), true)
	r := httptest.NewRequest("POST", "https://mail-connector.apps.test.privasys.org/tools/account", nil)
	r.Header.Set(PeerAppHeader, "0123456789abcdef0123456789abcdef")
	r.Header.Set(PeerVerifiedHeader, "true")
	err := s.authorise(r, "holder-1", grant.Read)
	if err == nil {
		t.Fatal("a holder whose folder is withdrawn must be refused")
	}
	if !strings.Contains(err.Error(), "not connected") || !strings.Contains(err.Error(), "connect_mailbox with no arguments") {
		t.Fatalf("the refusal must send the agent to connect_mailbox: %q", err)
	}
	if strings.Contains(err.Error(), "401") {
		t.Fatalf("a raw Drive status is not advice: %q", err)
	}
}
