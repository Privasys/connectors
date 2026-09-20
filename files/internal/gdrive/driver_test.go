// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package gdrive

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/files/internal/cloud"
)

func open(t *testing.T, g *fakeDrive, token string) *Driver {
	t.Helper()
	d, err := Open(context.Background(), Config{
		Base: g.srv.URL + "/drive/v3", Upload: g.srv.URL + "/upload/drive/v3", HTTP: g.srv.Client(),
		Token: func(context.Context) (string, error) { return token, nil },
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return d
}

func TestOpenProbesAndRefuses(t *testing.T) {
	g := newFakeDrive(t)
	d := open(t, g, "good")
	a, _ := d.Account(context.Background())
	if a.Provider != cloud.ProviderGoogle || a.User != "holder@gmail.com" || a.Name != "Holder Example" || a.DriveID != MyDrive {
		t.Fatalf("account: %+v", a)
	}
	if !g.sent("GET /drive/v3/about?fields=user,storageQuota") {
		t.Fatalf("the probe is about: %v", g.requests)
	}
	_, err := Open(context.Background(), Config{Base: g.srv.URL + "/drive/v3", HTTP: g.srv.Client(),
		Token: func(context.Context) (string, error) { return "expired", nil }})
	if !errors.Is(err, cloud.ErrLogin) {
		t.Fatalf("a refused token is ErrLogin: %v", err)
	}
}

func TestDrives(t *testing.T) {
	g := newFakeDrive(t)
	d := open(t, g, "good")
	drives, err := d.Drives(context.Background())
	if err != nil || len(drives) != 2 || drives[0].Kind != "personal" || drives[0].ID != MyDrive || drives[1].Kind != "shared" || drives[1].Name != "Team" {
		t.Fatalf("drives: %v %+v", err, drives)
	}
}

func TestListFolderNewestFirstAndPaged(t *testing.T) {
	g := newFakeDrive(t)
	d := open(t, g, "good")
	ctx := context.Background()
	items, next, err := d.List(ctx, "", "", 10, "")
	if err != nil || next != "" || len(items) != 2 || items[0].Name != "Documents" || !items[0].Folder || items[1].Name != "Survey" {
		t.Fatalf("root: %v %q %+v", err, next, items)
	}
	// By path, and by the folder's id; native documents say what they are.
	docs, _, err := d.List(ctx, "", "/Documents", 10, "")
	if err != nil || len(docs) != 3 || docs[0].Name != "Plan" || docs[0].Native != "document" || docs[1].Native != "spreadsheet" || docs[2].Name != "old.txt" {
		t.Fatalf("by path: %v %+v", err, docs)
	}
	if docs[2].Size != 5 || docs[2].MIME != "text/plain" || docs[2].Drive != MyDrive || docs[2].ModifiedBy != "Holder" {
		t.Fatalf("file facts: %+v", docs[2])
	}
	first, next, err := d.List(ctx, "", items[0].ID, 2, "")
	if err != nil || len(first) != 2 || next == "" {
		t.Fatalf("page 1: %v %+v %q", err, first, next)
	}
	second, next2, err := d.List(ctx, "", items[0].ID, 2, next)
	if err != nil || len(second) != 1 || second[0].Name != "old.txt" || next2 != "" {
		t.Fatalf("page 2: %v %+v %q", err, second, next2)
	}
	if _, _, err := d.List(ctx, "", "Nowhere/at/all", 10, ""); !errors.Is(err, cloud.ErrNotFound) {
		t.Fatalf("a missing path: %v", err)
	}
	// A shared drive: its root is the drive itself, and the listing is
	// scoped to it.
	team, _, err := d.List(ctx, sharedDrive, "", 10, "")
	if err != nil || len(team) != 1 || team[0].Name != "plan.md" || team[0].Drive != sharedDrive {
		t.Fatalf("shared drive: %v %+v", err, team)
	}
	if !g.sent("corpora=drive&driveId=0AShared") {
		t.Fatalf("scoped: %v", g.requests[len(g.requests)-1])
	}
}

func TestSearch(t *testing.T) {
	g := newFakeDrive(t)
	d := open(t, g, "good")
	hits, err := d.Search(context.Background(), "step one", "", 10)
	if err != nil || len(hits) != 1 || hits[0].Name != "Plan" {
		t.Fatalf("search: %v %+v", err, hits)
	}
	if !g.sent("fullText+contains+%27step+one%27+and+trashed+%3D+false") || !g.sent("corpora=allDrives") {
		t.Fatalf("the query: %v", g.requests[len(g.requests)-1])
	}
	// Quotes and backslashes in the query are escaped, not broken on.
	if _, err := d.Search(context.Background(), `it's \ here`, sharedDrive, 10); err != nil || !g.sent(`%27it%5C%27s+%5C%5C+here%27`) {
		t.Fatalf("escaping: %v %v", err, g.requests[len(g.requests)-1])
	}
	if _, err := d.Search(context.Background(), " ", "", 10); err == nil {
		t.Fatal("an empty query is refused")
	}
}

func TestFetchExportsAndDownloads(t *testing.T) {
	g := newFakeDrive(t)
	d := open(t, g, "good")
	ctx := context.Background()
	docs, _, _ := d.List(ctx, "", "Documents", 10, "")
	plan, budget, old := docs[0], docs[1], docs[2]

	c, err := d.Fetch(ctx, plan.ID, cloud.MaxDownload)
	if err != nil || !c.Exported || c.MIME != "text/plain" || string(c.Data) != "The plan\n\nStep one." {
		t.Fatalf("a Google Doc is exported as text: %v %+v", err, c)
	}
	c, err = d.Fetch(ctx, budget.ID, cloud.MaxDownload)
	if err != nil || !c.Exported || c.MIME != "text/csv" || string(c.Data) != "item,cost\nwidget,12" {
		t.Fatalf("a Sheet is exported as CSV: %v %+v", err, c)
	}
	c, err = d.Fetch(ctx, old.ID, cloud.MaxDownload)
	if err != nil || c.Exported || string(c.Data) != "older" || c.MIME != "text/plain" {
		t.Fatalf("a file is downloaded: %v %+v", err, c)
	}
	if !g.sent("/drive/v3/files/old?alt=media") {
		t.Fatalf("download: %v", g.requests)
	}
	// Past the bound, the metadata still comes back.
	c, err = d.Fetch(ctx, old.ID, 2)
	if !errors.Is(err, cloud.ErrTooLarge) || c.Item.Name != "old.txt" {
		t.Fatalf("too large: %v %+v", err, c.Item)
	}
	// An edit makes the listed id stale; a fresh listing reads the new one.
	g.touch("old", "newer")
	if _, err := d.Fetch(ctx, old.ID, cloud.MaxDownload); !errors.Is(err, cloud.ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	docs, _, _ = d.List(ctx, "", "Documents", 10, "")
	if c, err := d.Fetch(ctx, docs[0].ID, cloud.MaxDownload); err != nil || string(c.Data) != "newer" {
		t.Fatalf("fresh: %v %q", err, c.Data)
	}
	// A form has nothing to read; a folder is not content; a gone file is
	// not found.
	root, _, _ := d.List(ctx, "", "", 10, "")
	if _, err := d.Fetch(ctx, root[1].ID, cloud.MaxDownload); !errors.Is(err, cloud.ErrNoText) {
		t.Fatalf("a form: %v", err)
	}
	if _, err := d.Fetch(ctx, root[0].ID, cloud.MaxDownload); !errors.Is(err, cloud.ErrIsFolder) {
		t.Fatalf("a folder: %v", err)
	}
	g.remove("old")
	if _, err := d.Fetch(ctx, docs[0].ID, cloud.MaxDownload); !errors.Is(err, cloud.ErrNotFound) {
		t.Fatalf("removed: %v", err)
	}
}

func TestSaveIntoTheConnectorsFolderOnly(t *testing.T) {
	g := newFakeDrive(t)
	d := open(t, g, "good")
	ctx := context.Background()
	it, err := d.Save(ctx, "", "notes.md", []byte("# hi"), "text/markdown")
	if err != nil {
		t.Fatal(err)
	}
	folder := g.byName("root", "Privasys")
	if folder == nil || folder.mime != mimeFolder {
		t.Fatal("the folder is created at the root of My Drive")
	}
	if saved := g.byName(folder.id, "notes.md"); saved == nil || string(saved.content) != "# hi" || saved.mime != "text/markdown" || it.WebURL == "" || it.Name != "notes.md" {
		t.Fatalf("saved: %+v %+v", saved, it)
	}
	it2, err := d.Save(ctx, "", "notes.md", []byte("again"), "text/markdown")
	if err != nil || it2.Name != "notes (2).md" {
		t.Fatalf("suffix: %v %+v", err, it2)
	}
	it3, err := d.Save(ctx, "runs/today", "notes", []byte("x"), "text/markdown")
	if err != nil || it3.Name != "notes.md" {
		t.Fatalf("subfolder: %v %+v", err, it3)
	}
	runs := g.byName(folder.id, "runs")
	if runs == nil || g.byName(runs.id, "today") == nil || g.byName(g.byName(runs.id, "today").id, "notes.md") == nil {
		t.Fatal("the subfolders are made under the connector's folder")
	}
	for _, bad := range []string{"../Documents", "/Documents", "a/../b"} {
		if _, err := d.Save(ctx, bad, "x.md", []byte("x"), "text/markdown"); !errors.Is(err, cloud.ErrBadFolder) {
			t.Errorf("folder %q: %v", bad, err)
		}
	}
	if _, err := d.Save(ctx, "", "x.exe", []byte("x"), "text/plain"); !errors.Is(err, cloud.ErrBadName) {
		t.Errorf("name: %v", err)
	}
	// Every write named a parent under Privasys, never Documents.
	for _, r := range g.requests {
		if strings.HasPrefix(r, "POST") && strings.Contains(r, "docs") {
			t.Fatalf("a write reached outside the connector's folder: %s", r)
		}
	}
	for _, f := range g.files {
		if f.parent == "docs" && strings.HasPrefix(f.id, "new") {
			t.Fatalf("a file was written into Documents: %+v", f)
		}
	}
}

func TestChanges(t *testing.T) {
	g := newFakeDrive(t)
	d := open(t, g, "good")
	ctx := context.Background()
	pollEvery = 10 * time.Millisecond
	t.Cleanup(func() { pollEvery = 20 * time.Second })

	changes, cursor, err := d.Changes(ctx, "", 0)
	if err != nil || len(changes) != 0 || cursor == "" {
		t.Fatalf("baseline: %v %v %q", err, changes, cursor)
	}
	if !g.sent("/drive/v3/changes/startPageToken") {
		t.Fatalf("the baseline is a start page token: %v", g.requests)
	}
	changes, cursor2, err := d.Changes(ctx, cursor, 30*time.Millisecond)
	if err != nil || len(changes) != 0 || cursor2 != cursor {
		t.Fatalf("quiet: %v %v %q", err, changes, cursor2)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		g.touch("old", "newer")
		g.remove("form")
	}()
	start := time.Now()
	changes, cursor3, err := d.Changes(ctx, cursor2, 2*time.Second)
	if err != nil || len(changes) != 2 || time.Since(start) > time.Second || cursor3 == cursor2 {
		t.Fatalf("woken: %v %+v after %s", err, changes, time.Since(start))
	}
	kinds := map[string]string{}
	for _, c := range changes {
		if c.Kind == "removed" {
			kinds["removed"] = c.ID
		} else {
			kinds[c.Name] = c.Kind
			if got, err := d.Fetch(ctx, c.ID, cloud.MaxDownload); err != nil || string(got.Data) != "newer" {
				t.Fatalf("the feed's id reads the new version: %v %q", err, got.Data)
			}
		}
	}
	if kinds["old.txt"] != "changed" || kinds["removed"] == "" {
		t.Fatalf("kinds: %v", kinds)
	}
	// A token Drive no longer takes is a reset with a fresh token.
	changes, cursor4, err := d.Changes(ctx, "not-a-token", 10*time.Millisecond)
	if err != nil || len(changes) != 1 || changes[0].Kind != "reset" || cursor4 == "not-a-token" {
		t.Fatalf("reset: %v %+v %q", err, changes, cursor4)
	}
}
