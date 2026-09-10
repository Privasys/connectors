// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package store

import (
	"os"
	"path/filepath"
	"testing"
)

// The sealing key is the half of the pair this app holds. Losing it means
// every holder must connect their mailbox again, so its handling is pinned.
func TestSealKeyIsCreatedOnceAndReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "seal.key")

	first, err := loadOrCreateSealKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 {
		t.Fatalf("want a 32-byte key, got %d", len(first))
	}
	second, err := loadOrCreateSealKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("the key changed between reads, which would strand every stored credential")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Not asserted on Windows, where the mode is not meaningful.
	if info.Mode().Perm()&0o077 != 0 && os.Getenv("OS") == "" {
		t.Errorf("the sealing key is readable by others: %v", info.Mode().Perm())
	}
}

func TestSealKeyRejectsAWrongLengthFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seal.key")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateSealKey(path); err == nil {
		t.Fatal("a truncated key file should be refused, not padded or replaced")
	}
}

// A credential encrypted under one key must not open under another: that is
// the property that makes the ciphertext in someone's Drive inert on its own.
func TestCiphertextIsUselessWithoutTheKey(t *testing.T) {
	a, _ := loadOrCreateSealKey(filepath.Join(t.TempDir(), "a.key"))
	b, _ := loadOrCreateSealKey(filepath.Join(t.TempDir(), "b.key"))

	sealed, err := encrypt(a, []byte(`{"user":"x@example.com","secret":"app-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decrypt(b, sealed); err == nil {
		t.Fatal("the other key opened it")
	}
	plain, err := decrypt(a, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) == "" || !contains(string(plain), "app-password") {
		t.Fatalf("round trip lost the payload: %q", plain)
	}
	// And the ciphertext must not leak the plaintext.
	if contains(string(sealed), "app-password") || contains(string(sealed), "x@example.com") {
		t.Fatal("the plaintext is visible in the ciphertext")
	}
}

func TestEncryptIsNotDeterministic(t *testing.T) {
	key, _ := loadOrCreateSealKey(filepath.Join(t.TempDir(), "k"))
	one, _ := encrypt(key, []byte("same"))
	two, _ := encrypt(key, []byte("same"))
	if string(one) == string(two) {
		t.Fatal("two encryptions of the same value are identical, so the nonce is not random")
	}
}

func TestRedactedDropsTheSecret(t *testing.T) {
	a := Account{User: "x@example.com", Secret: "app-password"}.Redacted()
	if a.Secret != "" {
		t.Fatal("Redacted kept the secret")
	}
	if a.User == "" {
		t.Fatal("Redacted dropped what the holder needs to see")
	}
}

// OpenDrive must refuse a plain transport: on the platform the call to Drive
// has to be the attested leg, and a default client would talk to whatever
// answers the name.
func TestOpenDriveRefusesAnUnattestedTransport(t *testing.T) {
	if _, err := OpenDrive(nil, "drive.example", filepath.Join(t.TempDir(), "k"), nil); err == nil {
		t.Fatal("OpenDrive accepted a nil broker")
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
