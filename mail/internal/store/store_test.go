// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package store

import "testing"

func TestRedactedDropsTheSecret(t *testing.T) {
	a := Account{User: "x@example.com", Secret: "app-password"}.Redacted()
	if a.Secret != "" {
		t.Fatal("Redacted kept the secret")
	}
	if a.User == "" {
		t.Fatal("Redacted dropped what the holder needs to see")
	}
}
