// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package store holds the one thing a connector must keep across a restart:
// the credential for a linked mailbox.
//
// Even that does not live here in production. The design decision is that the
// connector holds NO durable user state: the credential is encrypted under a
// key sealed to the connector's own measurement, and the CIPHERTEXT is written
// to the user's own Drive. Two independent things must then hold for anyone
// else to use it, the user's tenant and the sealing key, and revoking the
// Drive grant strands it. That makes the user's own revoke button the kill
// switch, on a screen they already understand.
//
// The Store interface exists so that property is a seam rather than a promise.
// A local backend runs off-platform for development; the Drive backend is what
// ships. Nothing above this package knows which is in use.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrNoAccount means this user has not linked a mailbox.
var ErrNoAccount = errors.New("no mailbox linked for this user")

// Account is one linked mailbox.
//
// Secret is the only field that is a credential, and it is never returned by
// any API surface: the connector reads it to dial and nothing else. Everything
// else here exists so a user can be shown what they linked.
type Account struct {
	Provider string    `json:"provider"` // "imap", later "graph", "gmail"
	Host     string    `json:"host"`
	User     string    `json:"user"`
	Secret   string    `json:"secret"`
	LinkedAt time.Time `json:"linked_at"`

	// OwnDomains lets the agent tell colleagues from customers. Supplied by
	// the user at link time rather than guessed.
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

// ---------------------------------------------------------------- local

// Local is a development backend: encrypted files under a directory.
//
// It exists so the connector runs on a workstation without Drive, and so the
// interface above is exercised by something real rather than by a map. It is
// NOT the production backend, and the difference is not cosmetic: this keeps
// user secrets on the connector's own disk, which is exactly what the design
// says must not happen. Refuses to start unless explicitly asked for.
type Local struct {
	dir string
	key []byte
	mu  sync.Mutex
}

// OpenLocal opens a development store. The key must be 32 bytes.
func OpenLocal(dir string, key []byte) (*Local, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("local store: key must be 32 bytes, got %d", len(key))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("local store: %w", err)
	}
	return &Local{dir: dir, key: key}, nil
}

func (l *Local) path(sub string) string {
	// The subject is a platform identifier and can be long; hash-free but
	// sanitised, because it becomes a filename.
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, sub)
	return filepath.Join(l.dir, safe+".enc")
}

func (l *Local) Get(_ context.Context, sub string) (Account, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	raw, err := os.ReadFile(l.path(sub))
	if errors.Is(err, os.ErrNotExist) {
		return Account{}, ErrNoAccount
	}
	if err != nil {
		return Account{}, err
	}
	plain, err := decrypt(l.key, raw)
	if err != nil {
		return Account{}, fmt.Errorf("stored credential will not decrypt: %w", err)
	}
	var a Account
	if err := json.Unmarshal(plain, &a); err != nil {
		return Account{}, err
	}
	return a, nil
}

func (l *Local) Put(_ context.Context, sub string, a Account) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	plain, err := json.Marshal(a)
	if err != nil {
		return err
	}
	sealed, err := encrypt(l.key, plain)
	if err != nil {
		return err
	}
	return os.WriteFile(l.path(sub), sealed, 0o600)
}

func (l *Local) Delete(_ context.Context, sub string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	err := os.Remove(l.path(sub))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (l *Local) Close() error { return nil }

// ---------------------------------------------------------------- crypto

// encrypt is AES-256-GCM with a random nonce prefixed to the ciphertext.
//
// The same primitive serves the Drive backend: what changes there is only
// where the key comes from (sealed to the measurement) and where the
// ciphertext goes (the user's tenant), not how it is protected.
func encrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func decrypt(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// ---------------------------------------------------------------- drive

// Drive is the production backend: ciphertext in the user's own Drive folder,
// under a key sealed to this connector's measurement.
//
// Not implemented yet. It needs the capability protocol (the wallet approving
// a storage.folder for this app) and the runtime's per-app sealing key, both
// of which exist on the platform and neither of which is wired here. The type
// is declared now so the seam is real and the rest of the connector is written
// against it rather than against the local backend.
//
// Operational rule for whoever builds it: the sealing key goes under the
// upgrade gate. A release that rotates it silently is a re-link event for
// every user, and must be planned as one.
type Drive struct{}

func (d *Drive) Get(context.Context, string) (Account, error) {
	return Account{}, errors.New("the Drive-backed credential store is not built yet")
}
func (d *Drive) Put(context.Context, string, Account) error {
	return errors.New("the Drive-backed credential store is not built yet")
}
func (d *Drive) Delete(context.Context, string) error {
	return errors.New("the Drive-backed credential store is not built yet")
}
func (d *Drive) Close() error { return nil }
