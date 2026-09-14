// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
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
	if !strings.Contains(msg, "not connected") || !strings.Contains(msg, "connect_mailbox") || !strings.Contains(msg, "question tool") {
		t.Fatalf("the refusal must have the agent collect the details in the conversation and call connect_mailbox: %q", msg)
	}
	if !strings.Contains(msg, "Do not request access") {
		t.Fatalf("the refusal must stop the agent asking the wallet first: %q", msg)
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
