// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/connectors/mail/internal/broker"
)

// DriveStore keeps each holder's credential as ciphertext in that holder's own
// Drive.
//
// Two independent things must hold before anyone can use a credential: the
// ciphertext, which lives in the holder's tenant and which they can revoke
// this app's access to, and the sealing key, which lives on this app's
// encrypted volume and which only this measurement can read. Neither alone is
// enough, and the holder controls the first.
//
// That is what makes the Drive "apps with access" revoke a real kill switch
// rather than a request someone honours. It also means this service can be
// redeployed, or lose its volume, without leaking anything: the ciphertext it
// left behind is inert.
//
// OPERATIONAL RULE for whoever changes this: the sealing key goes under the
// upgrade gate. A release that rotates it is a re-link event for every holder,
// and must be planned as one rather than discovered.
type DriveStore struct {
	broker *broker.Client
	http   *http.Client

	// driveHost is the resource service, resolved by identity by the runtime
	// and passed in, never read from a request.
	driveHost string

	mu     sync.Mutex
	key    []byte
	pubkey string
}

// appGrantEnvelope is Drive's token payload. Field names and the wire form
// are Drive's, not ours: `Authorization: AppGrant <b64url(json)>.<b64url(sig)>`.
type appGrantEnvelope struct {
	Iss   string   `json:"iss"`
	Aud   string   `json:"aud"`
	Sub   string   `json:"sub"`  // tenant id
	Node  string   `json:"node"` // node id, the granted folder
	Scope []string `json:"scope"`
	MRTD  string   `json:"mrtd"`
	JTI   string   `json:"jti"` // the capability id, which is how Drive finds the grant
	Iat   int64    `json:"iat"`
	Exp   int64    `json:"exp"`
	PK    string   `json:"pk"`
}

const (
	driveAudience = "privasys-drive"
	// credentialPath is the one file this app writes into the holder's folder.
	credentialPath = "credential.enc"
	// tokenLife is short on purpose: a proof is minted per request and never
	// stored, so nothing useful is left lying around if one leaks.
	tokenLife = 2 * time.Minute
)

// OpenDrive builds the production store.
func OpenDrive(b *broker.Client, driveHost, sealKeyPath string, transport http.RoundTripper) (*DriveStore, error) {
	if b == nil {
		return nil, errors.New("the Drive store needs a runtime capability broker")
	}
	if strings.TrimSpace(driveHost) == "" {
		return nil, errors.New("the Drive store needs the resource service's host")
	}
	key, err := loadOrCreateSealKey(sealKeyPath)
	if err != nil {
		return nil, err
	}
	// The transport is injected because on the platform it must be the
	// attested leg: mutual RA-TLS to a peer whose measurement is pinned. A
	// plain client here would talk to whatever answers the name.
	if transport == nil {
		return nil, errors.New("the Drive store needs an attested transport; a default client would not verify the peer")
	}
	return &DriveStore{
		broker: b, driveHost: driveHost, key: key,
		http: &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}, nil
}

// loadOrCreateSealKey reads the per-app key from the encrypted volume, making
// it once on first boot.
//
// It is per-APP, not per-holder, which is the distinction that keeps this
// consistent with "the connector holds no durable user state": a key that
// unlocks nothing on its own is not user data.
func loadOrCreateSealKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("no sealing key path")
	}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(raw) != 32 {
			return nil, fmt.Errorf("sealing key at %s is %d bytes, want 32", path, len(raw))
		}
		return raw, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	// O_EXCL: two workers starting together must not each write a key and
	// leave one of them unable to read what the other stored.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateSealKey(path)
		}
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(key); err != nil {
		return nil, err
	}
	return key, nil
}

// coords resolves where this holder's folder is, and refuses politely when
// they have not approved us.
func (d *DriveStore) coords(ctx context.Context, sub string) (broker.Status, error) {
	st, err := d.broker.Status(ctx, sub)
	if err != nil {
		return st, err
	}
	switch {
	case st.Declined:
		return st, broker.ErrDeclined
	case !st.Approved:
		return st, broker.ErrNotApproved
	case st.TenantID() == "" || st.NodeID() == "":
		return st, errors.New("the approval carries no folder coordinates")
	}
	return st, nil
}

// token mints one holder-of-key proof for one request.
func (d *DriveStore) token(ctx context.Context, st broker.Status, scope []string) (string, error) {
	now := time.Now().UTC()
	env := appGrantEnvelope{
		Iss:   "https://privasys.id",
		Aud:   driveAudience,
		Sub:   st.TenantID(),
		Node:  st.NodeID(),
		Scope: scope,
		JTI:   st.CapabilityID,
		Iat:   now.Unix(),
		Exp:   now.Add(tokenLife).Unix(),
	}
	// The envelope carries the public half, and the signature must cover the
	// exact bytes Drive will verify, so the key has to be known BEFORE
	// signing. It is stable per app, so it is learned once and then reused;
	// the alternative, signing a draft to discover the key and signing again,
	// costs two round trips on every single request.
	pub, err := d.bindingKey(ctx)
	if err != nil {
		return "", err
	}
	env.PK = pub
	body, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	sig, signedWith, err := d.broker.Sign(ctx, body)
	if err != nil {
		return "", err
	}
	if signedWith != pub {
		// The manager rotated the app's key between learning it and using it.
		// Presenting a proof whose stated key is not the one that signed it
		// would be rejected by Drive anyway, and confusingly.
		d.forgetBindingKey()
		return "", errors.New("the app's binding key changed while minting a proof; retry")
	}
	return "AppGrant " + base64.RawURLEncoding.EncodeToString(body) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// bindingKey returns the app's public binding key, learning it once.
//
// There is no endpoint that just returns it, so it is learned from a
// signature over a throwaway payload. That payload is deliberately not a
// valid envelope: a signature the app asks for should never be one anybody
// could present as a capability proof.
func (d *DriveStore) bindingKey(ctx context.Context) (string, error) {
	d.mu.Lock()
	if d.pubkey != "" {
		defer d.mu.Unlock()
		return d.pubkey, nil
	}
	d.mu.Unlock()

	_, pub, err := d.broker.Sign(ctx, []byte("privasys/mail-connector/binding-key-probe"))
	if err != nil {
		return "", err
	}
	d.mu.Lock()
	d.pubkey = pub
	d.mu.Unlock()
	return pub, nil
}

func (d *DriveStore) forgetBindingKey() {
	d.mu.Lock()
	d.pubkey = ""
	d.mu.Unlock()
}

func (d *DriveStore) request(ctx context.Context, st broker.Status, method, path string, body io.Reader, scope []string) (*http.Response, error) {
	tok, err := d.token(ctx, st, scope)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%s/v1/tenants/%s/path?root=%s&path=%s",
		d.driveHost, st.TenantID(), st.NodeID(), path)
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-Drive-Parents", "create")
	}
	return d.http.Do(req)
}

func (d *DriveStore) Get(ctx context.Context, sub string) (Account, error) {
	st, err := d.coords(ctx, sub)
	if err != nil {
		return Account{}, err
	}
	res, err := d.request(ctx, st, http.MethodGet, credentialPath, nil, []string{"read"})
	if err != nil {
		return Account{}, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return Account{}, ErrNoAccount
	}
	if res.StatusCode/100 != 2 {
		return Account{}, fmt.Errorf("drive answered %d reading the credential", res.StatusCode)
	}
	sealed, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return Account{}, err
	}
	plain, err := decrypt(d.key, sealed)
	if err != nil {
		// The ciphertext is there and will not open. Almost always the sealing
		// key changed, which is a re-link event, so say that rather than
		// "corrupt".
		return Account{}, fmt.Errorf(
			"the stored credential will not decrypt with this app's sealing key; " +
				"if this app was upgraded, the holder must connect their mailbox again")
	}
	var a Account
	if err := json.Unmarshal(plain, &a); err != nil {
		return Account{}, err
	}
	return a, nil
}

func (d *DriveStore) Put(ctx context.Context, sub string, a Account) error {
	st, err := d.coords(ctx, sub)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(a)
	if err != nil {
		return err
	}
	sealed, err := encrypt(d.key, plain)
	if err != nil {
		return err
	}
	res, err := d.request(ctx, st, http.MethodPut, credentialPath, bytes.NewReader(sealed), []string{"read", "write"})
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("drive answered %d writing the credential", res.StatusCode)
	}
	return nil
}

// Delete writes an empty file rather than removing the node.
//
// Deleting would need a delete scope this app does not ask for, and asking for
// one so that disconnecting looks tidier would widen what the holder approved
// for the sake of housekeeping. An empty credential is as unusable as an
// absent one.
func (d *DriveStore) Delete(ctx context.Context, sub string) error {
	st, err := d.coords(ctx, sub)
	if errors.Is(err, broker.ErrNotApproved) || errors.Is(err, ErrNoAccount) {
		return nil
	}
	if err != nil {
		return err
	}
	res, err := d.request(ctx, st, http.MethodPut, credentialPath, bytes.NewReader(nil), []string{"read", "write"})
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("drive answered %d clearing the credential", res.StatusCode)
	}
	return nil
}

func (d *DriveStore) Close() error { return nil }

// AskApproval triggers the wallet push for a holder who has not approved yet.
// A user gesture, never automatic.
func (d *DriveStore) AskApproval(ctx context.Context, sub string, retry bool) error {
	return d.broker.Request(ctx, sub, retry)
}
