// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package grant is the connector's half of the capability protocol: what the
// wallet mints when a holder approves, and what every tool call is checked
// against.
//
// The connector is the RESOURCE SERVICE here, the same role Drive plays for
// storage. That matters because it decides where each rule lives. The wallet
// is the attestation-verification point at approval time; this package is the
// enforcement point at request time. Neither trusts the other's word for the
// thing it owns.
//
// Three properties are load-bearing, and each one exists because its absence
// was a real defect somewhere:
//
//   - The OWNER is derived, never named. A request may not say whose mailbox
//     it wants; the holder is whoever the wallet authenticated. An app that
//     could name a tenant could aim a capability at someone else's data while
//     the approval screen still read truthfully.
//   - The SUBJECT is verified, never supplied. The app id comes from the
//     attested peer identity, not from the request body.
//   - PERMISSIONS are mirrored exactly from what the wallet displayed. Not
//     re-derived from the app's own request, because then the service could
//     mint something wider than the sentence the holder read. Silently
//     narrowing breaks the same promise as widening, so an unknown value is
//     refused rather than dropped.
package grant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind is the only capability this service issues. The vocabulary is closed on
// the wallet side too, and both ends must agree or the holder is shown a
// sentence that does not match what is enforced.
const Kind = "mail.mailbox"

// Permission is the closed vocabulary. Write means labels and drafts. There is
// deliberately no send permission, because there is no send.
type Permission string

const (
	Read  Permission = "read"
	Write Permission = "write"
)

var (
	ErrNoGrant  = errors.New("no live capability for this app and this user")
	ErrExpired  = errors.New("the capability has expired")
	ErrScope    = errors.New("the capability does not cover this")
	ErrBadInput = errors.New("the capability request is malformed")
)

// Grant is one holder's standing approval for one app.
type Grant struct {
	ID string `json:"id"`

	// Subject is the app the capability belongs to, as "app:<32 hex>". Taken
	// from the wallet's VERIFIED view of the requester at approval time.
	Subject string `json:"subject"`

	// UserSub is the holder. Resolved by this service from the authenticated
	// caller, never read out of the request.
	UserSub string `json:"-"`

	Permissions []Permission `json:"permissions"`
	IssuedAt    time.Time    `json:"issued_at"`
	ExpiresAt   time.Time    `json:"expires_at"`

	// AppName is advisory, for the "apps with access" list. Never used in a
	// decision: names are not identities.
	AppName string `json:"app_name,omitempty"`
}

func (g Grant) Live(now time.Time) bool { return now.Before(g.ExpiresAt) }

func (g Grant) Allows(p Permission) bool {
	for _, have := range g.Permissions {
		if have == p {
			return true
		}
	}
	return false
}

// NormaliseSubject accepts the forms a peer identity arrives in and returns
// the canonical "app:<32 hex>".
//
// Identity, not measurement: a release must not force every holder to approve
// again, so the subject is the app id and the image digest is checked
// elsewhere by the dependency machinery.
func NormaliseSubject(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "app:")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return "", fmt.Errorf("%w: an app id is 32 hex characters, got %d", ErrBadInput, len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("%w: an app id must be hex", ErrBadInput)
	}
	return "app:" + s, nil
}

// ParsePermissions mirrors what the wallet displayed.
func ParsePermissions(in []string) ([]Permission, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("%w: no permissions were requested", ErrBadInput)
	}
	seen := map[Permission]bool{}
	var out []Permission
	for _, s := range in {
		p := Permission(strings.ToLower(strings.TrimSpace(s)))
		switch p {
		case Read, Write:
		default:
			// Refused, not dropped. Dropping would mint something narrower
			// than the sentence the holder read, which is its own kind of lie.
			return nil, fmt.Errorf("%w: %q is not a permission this service issues", ErrBadInput, s)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// Request is the wallet's mint call, forwarded from the requesting app but
// with the fields that matter replaced by what the wallet VERIFIED.
type Request struct {
	Nonce string `json:"nonce"`

	// SubjectAppID is the wallet's verified view of who is asking, from the
	// attestation rather than from the payload.
	SubjectAppID string `json:"subject_app_id"`

	BindingPubKey string   `json:"binding_pubkey"`
	ExpiresUnix   int64    `json:"expires_unix"`
	Kind          string   `json:"kind"`
	Permissions   []string `json:"permissions"`

	// Opaque, forwarded verbatim by the wallet, interpreted here. It must NOT
	// be able to name a mailbox or a holder: see Validate.
	Req map[string]any `json:"request"`
}

// maxLifetime bounds what this service will issue whatever the wallet asks.
// The wallet chooses the expiry per kind and is trusted to be sane, but a
// resource service that will mint an unbounded capability on request has no
// business holding anyone's mail.
const maxLifetime = 180 * 24 * time.Hour

// Validate checks everything that must be true before a grant is minted.
func (r Request) Validate(now time.Time) (subject string, perms []Permission, err error) {
	if strings.TrimSpace(r.Nonce) == "" {
		return "", nil, fmt.Errorf("%w: no nonce", ErrBadInput)
	}
	if r.Kind != Kind {
		return "", nil, fmt.Errorf("%w: this service issues %q, not %q", ErrBadInput, Kind, r.Kind)
	}
	subject, err = NormaliseSubject(r.SubjectAppID)
	if err != nil {
		return "", nil, err
	}
	perms, err = ParsePermissions(r.Permissions)
	if err != nil {
		return "", nil, err
	}
	exp := time.Unix(r.ExpiresUnix, 0)
	if r.ExpiresUnix == 0 || !exp.After(now) {
		return "", nil, fmt.Errorf("%w: the expiry is missing or already past", ErrBadInput)
	}
	if exp.Sub(now) > maxLifetime {
		return "", nil, fmt.Errorf("%w: %s is longer than this service will issue", ErrBadInput, exp.Sub(now).Round(time.Hour))
	}

	// S4, and the reason this check exists at all: the first design let the
	// requesting app compose a body that could name a tenant, so an app could
	// aim the capability at data the holder happens to have rights in. The
	// holder would read a truthful screen and approve the wrong thing.
	for _, forbidden := range []string{"user", "sub", "subject", "account", "mailbox", "tenant", "owner", "holder", "email", "address"} {
		if _, ok := r.Req[forbidden]; ok {
			return "", nil, fmt.Errorf(
				"%w: a request may not name whose mailbox it wants (%q); the holder is whoever approved it",
				ErrBadInput, forbidden)
		}
	}
	return subject, perms, nil
}

// ---------------------------------------------------------------- store

// Store holds grants. In production this is the user's own Drive, like the
// credential: revoking there is what makes the holder's own revoke button the
// real thing rather than a request we honour.
type Store interface {
	Mint(ctx context.Context, userSub string, g Grant) (Grant, error)
	// Find returns the live grant for one app acting for one user.
	Find(ctx context.Context, userSub, subject string) (Grant, error)
	List(ctx context.Context, userSub string) ([]Grant, error)
	Revoke(ctx context.Context, userSub, id string) error
}

// Memory is an in-process store. Enough to run and to test; it loses grants on
// restart, which for a capability is the safe direction to fail.
type Memory struct {
	mu sync.Mutex
	by map[string][]Grant // userSub -> grants
}

func NewMemory() *Memory { return &Memory{by: map[string][]Grant{}} }

func (m *Memory) Mint(_ context.Context, userSub string, g Grant) (Grant, error) {
	if strings.TrimSpace(userSub) == "" {
		return Grant{}, fmt.Errorf("%w: no holder", ErrBadInput)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	g.ID = newID()
	g.UserSub = userSub
	g.IssuedAt = time.Now()

	// One live grant per app per holder. Re-approving replaces rather than
	// accumulates, so the "apps with access" list stays something a person can
	// read and a revoke removes the access rather than one of several copies.
	kept := m.by[userSub][:0]
	for _, old := range m.by[userSub] {
		if old.Subject != g.Subject {
			kept = append(kept, old)
		}
	}
	m.by[userSub] = append(kept, g)
	return g, nil
}

func (m *Memory) Find(_ context.Context, userSub, subject string) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, g := range m.by[userSub] {
		if g.Subject != subject {
			continue
		}
		if !g.Live(now) {
			return Grant{}, ErrExpired
		}
		return g, nil
	}
	return Grant{}, ErrNoGrant
}

func (m *Memory) List(_ context.Context, userSub string) ([]Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var out []Grant
	for _, g := range m.by[userSub] {
		if g.Live(now) {
			out = append(out, g)
		}
	}
	return out, nil
}

func (m *Memory) Revoke(_ context.Context, userSub, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.by[userSub][:0]
	found := false
	for _, g := range m.by[userSub] {
		if g.ID == id {
			found = true
			continue
		}
		kept = append(kept, g)
	}
	m.by[userSub] = kept
	if !found {
		return ErrNoGrant
	}
	return nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
