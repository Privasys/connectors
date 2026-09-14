// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Privasys/connectors/mail/internal/grant"
)

// mapFiles stands in for the holder's Drive: one file per holder and path.
type mapFiles struct {
	data   map[string][]byte
	reads  int
	writes int
}

func (m *mapFiles) readSealed(_ context.Context, sub, path string) ([]byte, bool, error) {
	m.reads++
	b, ok := m.data[sub+"/"+path]
	return b, ok, nil
}

func (m *mapFiles) writeSealed(_ context.Context, sub, path string, plain []byte) error {
	m.writes++
	m.data[sub+"/"+path] = plain
	return nil
}

func liveGrant(subject string) grant.Grant {
	return grant.Grant{Subject: subject, Permissions: []grant.Permission{grant.Read}, ExpiresAt: time.Now().Add(time.Hour)}
}

func TestGrantsSurviveAFreshStoreOverTheSameFiles(t *testing.T) {
	files := &mapFiles{data: map[string][]byte{}}
	first := newGrantsOver(files)
	ctx := context.Background()
	minted, err := first.Mint(ctx, "holder-1", liveGrant("app:"+"0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	// A restart is a new store over the same holder files.
	second := newGrantsOver(files)
	found, err := second.Find(ctx, "holder-1", minted.Subject)
	if err != nil {
		t.Fatalf("the grant did not survive the restart: %v", err)
	}
	if found.ID != minted.ID || found.UserSub != "holder-1" {
		t.Fatalf("found %+v, want the minted grant for the holder", found)
	}
}

func TestReapprovingReplacesAndRevokeRemoves(t *testing.T) {
	files := &mapFiles{data: map[string][]byte{}}
	g := newGrantsOver(files)
	ctx := context.Background()
	sub := "app:" + "0123456789abcdef0123456789abcdef"
	a, _ := g.Mint(ctx, "h", liveGrant(sub))
	b, _ := g.Mint(ctx, "h", liveGrant(sub))
	list, _ := g.List(ctx, "h")
	if len(list) != 1 || list[0].ID != b.ID {
		t.Fatalf("re-approving must replace, got %d grants (first %s)", len(list), a.ID)
	}
	if err := g.Revoke(ctx, "h", b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Find(ctx, "h", sub); !errors.Is(err, grant.ErrNoGrant) {
		t.Fatalf("after revoke want ErrNoGrant, got %v", err)
	}
	if err := g.Revoke(ctx, "h", b.ID); !errors.Is(err, grant.ErrNoGrant) {
		t.Fatalf("revoking twice must say there is nothing to revoke, got %v", err)
	}
}

func TestExpiredGrantIsReportedAsExpired(t *testing.T) {
	files := &mapFiles{data: map[string][]byte{}}
	g := newGrantsOver(files)
	ctx := context.Background()
	gr := liveGrant("app:" + "0123456789abcdef0123456789abcdef")
	gr.ExpiresAt = time.Now().Add(-time.Minute)
	if _, err := g.Mint(ctx, "h", gr); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Find(ctx, "h", gr.Subject); !errors.Is(err, grant.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	if list, _ := g.List(ctx, "h"); len(list) != 0 {
		t.Fatalf("an expired grant must not be listed as live")
	}
}

func TestChecksAreServedFromTheCacheBetweenWrites(t *testing.T) {
	files := &mapFiles{data: map[string][]byte{}}
	g := newGrantsOver(files)
	ctx := context.Background()
	sub := "app:" + "0123456789abcdef0123456789abcdef"
	if _, err := g.Mint(ctx, "h", liveGrant(sub)); err != nil {
		t.Fatal(err)
	}
	reads := files.reads
	for i := 0; i < 5; i++ {
		if _, err := g.Find(ctx, "h", sub); err != nil {
			t.Fatal(err)
		}
	}
	if files.reads != reads {
		t.Fatalf("five checks cost %d Drive reads, want 0 within the cache window", files.reads-reads)
	}
}
