// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRedactedDropsTheSecret(t *testing.T) {
	a := Account{User: "x@example.com", Secret: "app-password", RefreshToken: "rt", AccessToken: "at", Expiry: time.Now()}.Redacted()
	if a.Secret != "" || a.RefreshToken != "" || a.AccessToken != "" || !a.Expiry.IsZero() {
		t.Fatal("Redacted kept a credential")
	}
	if a.User == "" {
		t.Fatal("Redacted dropped what the holder needs to see")
	}
}

// A token set is never serialised, whatever asks: belt and braces beside
// Redacted, because an account tool that forgot to redact would otherwise
// hand an agent a bearer for the mailbox.
func TestTokensAreNeverSerialised(t *testing.T) {
	raw, _ := json.Marshal(Account{Provider: ProviderGoogle, User: "x@gmail.com", RefreshToken: "rt-bearer", AccessToken: "at-bearer"})
	if strings.Contains(string(raw), "bearer") {
		t.Fatalf("a token reached the JSON: %s", raw)
	}
	if !(Account{Provider: ProviderMicrosoft}).SignedIn() || (Account{Provider: ProviderIMAP}).SignedIn() {
		t.Fatal("SignedIn tells a sign-in from a password")
	}
}
