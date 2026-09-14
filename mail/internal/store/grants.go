// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/connectors/mail/internal/grant"
)

// DriveGrants keeps each holder's standing capabilities in that holder's own
// Drive, beside the credential and sealed the same way.
//
// Why not in memory: a capability is what the wallet minted when the holder
// approved, and the harness's runtime remembers that approval durably. A
// connector that forgot it on every restart refused every tool call until
// the holder tapped the wallet again, while the harness still believed the
// resource approved (found 2026-09-14). And an unattended routine, which runs
// while the holder is not looking, can only hold a capability that survives
// the process.
//
// Why the holder's Drive and not this app's volume: the same argument as the
// credential. The holder's revoke of this app's folder is then the kill
// switch for the capability too, and a redeployed or wiped connector leaves
// nothing behind that still works.
//
// The file is one sealed JSON list per holder. A holder has a handful of apps
// at most, so the list is read and rewritten whole; a short cache keeps the
// per-call check from costing a Drive round trip.
type DriveGrants struct {
	files sealedFiles

	mu    sync.Mutex
	cache map[string]cachedGrants // holder -> list
}

// sealedFiles is the little of the Drive store the grant store needs: a
// sealed file per holder, read and written whole. The Drive store implements
// it; the tests use a map.
type sealedFiles interface {
	readSealed(ctx context.Context, sub, path string) (plain []byte, found bool, err error)
	writeSealed(ctx context.Context, sub, path string, plain []byte) error
}

type cachedGrants struct {
	list []grant.Grant
	at   time.Time
}

const (
	// grantsPath is the second file this app writes into the holder's folder.
	grantsPath = "grants.enc"
	// grantsCacheTTL bounds how long a revoke made elsewhere (another replica,
	// or the holder's own Drive) can go unnoticed here.
	grantsCacheTTL = time.Minute
)

// NewDriveGrants builds the grant store over an open Drive credential store.
func NewDriveGrants(d *DriveStore) *DriveGrants {
	return newGrantsOver(d)
}

func newGrantsOver(f sealedFiles) *DriveGrants {
	return &DriveGrants{files: f, cache: map[string]cachedGrants{}}
}

var _ grant.Store = (*DriveGrants)(nil)

// load returns the holder's list, from the cache when it is fresh.
func (g *DriveGrants) load(ctx context.Context, sub string) ([]grant.Grant, error) {
	g.mu.Lock()
	c, ok := g.cache[sub]
	g.mu.Unlock()
	if ok && time.Since(c.at) < grantsCacheTTL {
		return c.list, nil
	}
	plain, found, err := g.files.readSealed(ctx, sub, grantsPath)
	if err != nil {
		return nil, err
	}
	var list []grant.Grant
	if found && len(plain) > 0 {
		if err := json.Unmarshal(plain, &list); err != nil {
			return nil, fmt.Errorf("the stored capabilities do not parse: %w", err)
		}
	}
	for i := range list {
		list[i].UserSub = sub
	}
	g.mu.Lock()
	g.cache[sub] = cachedGrants{list: list, at: time.Now()}
	g.mu.Unlock()
	return list, nil
}

// save rewrites the holder's list and refreshes the cache.
func (g *DriveGrants) save(ctx context.Context, sub string, list []grant.Grant) error {
	plain, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if err := g.files.writeSealed(ctx, sub, grantsPath, plain); err != nil {
		return err
	}
	for i := range list {
		list[i].UserSub = sub
	}
	g.mu.Lock()
	g.cache[sub] = cachedGrants{list: list, at: time.Now()}
	g.mu.Unlock()
	return nil
}

func (g *DriveGrants) Mint(ctx context.Context, userSub string, gr grant.Grant) (grant.Grant, error) {
	if strings.TrimSpace(userSub) == "" {
		return grant.Grant{}, fmt.Errorf("%w: no holder", grant.ErrBadInput)
	}
	list, err := g.load(ctx, userSub)
	if err != nil {
		return grant.Grant{}, err
	}
	gr.ID = grant.NewID()
	gr.UserSub = userSub
	gr.IssuedAt = time.Now()
	// One live grant per app per holder, as in the memory store: re-approving
	// replaces, so a revoke removes the access rather than one copy of it.
	kept := make([]grant.Grant, 0, len(list)+1)
	for _, old := range list {
		if old.Subject != gr.Subject {
			kept = append(kept, old)
		}
	}
	kept = append(kept, gr)
	if err := g.save(ctx, userSub, kept); err != nil {
		return grant.Grant{}, err
	}
	return gr, nil
}

func (g *DriveGrants) Find(ctx context.Context, userSub, subject string) (grant.Grant, error) {
	list, err := g.load(ctx, userSub)
	if err != nil {
		return grant.Grant{}, err
	}
	now := time.Now()
	for _, gr := range list {
		if gr.Subject != subject {
			continue
		}
		if !gr.Live(now) {
			return grant.Grant{}, grant.ErrExpired
		}
		return gr, nil
	}
	return grant.Grant{}, grant.ErrNoGrant
}

func (g *DriveGrants) List(ctx context.Context, userSub string) ([]grant.Grant, error) {
	list, err := g.load(ctx, userSub)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out []grant.Grant
	for _, gr := range list {
		if gr.Live(now) {
			out = append(out, gr)
		}
	}
	return out, nil
}

func (g *DriveGrants) Revoke(ctx context.Context, userSub, id string) error {
	list, err := g.load(ctx, userSub)
	if err != nil {
		return err
	}
	kept := make([]grant.Grant, 0, len(list))
	found := false
	for _, gr := range list {
		if gr.ID == id {
			found = true
			continue
		}
		kept = append(kept, gr)
	}
	if !found {
		return grant.ErrNoGrant
	}
	return g.save(ctx, userSub, kept)
}

// ErrNoFolder is what a grant operation returns when the holder has given
// this app no folder yet: there is nowhere a grant could be kept or found.
var ErrNoFolder = errors.New("the holder has not approved this app's Drive folder, so no capability can be kept for them")
