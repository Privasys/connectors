// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package graph

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/files/internal/cloud"
)

func open(t *testing.T, g *fakeGraph, token string) *Driver {
	t.Helper()
	d, err := Open(context.Background(), Config{
		Base: g.srv.URL + "/v1.0", HTTP: g.srv.Client(),
		Token: func(context.Context) (string, error) { return token, nil },
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return d
}

func TestOpenProbesAndRefuses(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g, "good")
	a, _ := d.Account(context.Background())
	if a.Provider != cloud.ProviderMicrosoft || a.User != "holder@example.org" || a.Name != "Holder Example" || a.DriveID != myDrive || a.DriveType != "business" {
		t.Fatalf("account: %+v", a)
	}
	if !g.sent("GET /v1.0/me?") || !g.sent("GET /v1.0/me/drive?") {
		t.Fatalf("the probe is /me and /me/drive: %v", g.requests)
	}
	_, err := Open(context.Background(), Config{Base: g.srv.URL + "/v1.0", HTTP: g.srv.Client(),
		Token: func(context.Context) (string, error) { return "expired", nil }})
	if !errors.Is(err, cloud.ErrLogin) {
		t.Fatalf("a refused token is ErrLogin: %v", err)
	}
}

func TestDrives(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g, "good")
	drives, err := d.Drives(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, dr := range drives {
		names = append(names, dr.Kind+":"+dr.Name)
	}
	want := "personal:OneDrive for work sharepoint:Documents sharepoint:Recent Library"
	if strings.Join(names, " ") != want {
		t.Fatalf("drives: %v", names)
	}
	if drives[1].Site != "Team Site" || drives[1].ID != siteDrive {
		t.Fatalf("the library names its site: %+v", drives[1])
	}
	// A personal account: the SharePoint legs fail and the answer is the
	// personal drive, not an error.
	g.personal = true
	drives, err = d.Drives(context.Background())
	if err != nil || len(drives) < 1 || drives[0].Kind != "personal" {
		t.Fatalf("personal account: %v %+v", err, drives)
	}
}

func TestListFolderNewestFirstAndPaged(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g, "good")
	ctx := context.Background()
	items, next, err := d.List(ctx, "", "", 10, "")
	if err != nil || next != "" {
		t.Fatalf("root: %v %q", err, next)
	}
	if len(items) != 2 || items[0].Name != "video.mp4" || items[1].Name != "Documents" || !items[1].Folder {
		t.Fatalf("root listing newest first: %+v", items)
	}
	if items[1].Children != 2 || items[1].Path != "/" || items[1].Drive != myDrive {
		t.Fatalf("folder facts: %+v", items[1])
	}
	// By path, by the folder's id, and paged one at a time.
	byPath, _, err := d.List(ctx, "", "Documents", 10, "")
	if err != nil || len(byPath) != 2 || byPath[0].Name != "memo.docx" || byPath[0].Path != "/Documents" {
		t.Fatalf("by path: %v %+v", err, byPath)
	}
	first, next, err := d.List(ctx, "", items[1].ID, 1, "")
	if err != nil || len(first) != 1 || first[0].Name != "memo.docx" || next == "" {
		t.Fatalf("page 1: %v %+v %q", err, first, next)
	}
	second, next2, err := d.List(ctx, "", "", 1, next)
	if err != nil || len(second) != 1 || second[0].Name != "old.txt" || next2 != "" {
		t.Fatalf("page 2: %v %+v %q", err, second, next2)
	}
	// A page token that does not point at Graph is refused before a
	// bearer goes anywhere.
	if _, _, err := d.List(ctx, "", "", 1, encodePage("https://evil.example/x")); err == nil || g.sent("evil") {
		t.Fatal("a foreign page token must be refused")
	}
	// Another drive, by id.
	site, _, err := d.List(ctx, siteDrive, "", 10, "")
	if err != nil || len(site) != 1 || site[0].Name != "plan.md" || site[0].Drive != siteDrive {
		t.Fatalf("site drive: %v %+v", err, site)
	}
	if _, _, err := d.List(ctx, "", "Nowhere", 10, ""); !errors.Is(err, cloud.ErrNotFound) {
		t.Fatalf("a missing path: %v", err)
	}
	// A library that will not sort on the server is sorted here.
	g.noOrderBy = true
	items, _, err = d.List(ctx, "", "", 10, "")
	if err != nil || len(items) != 2 || items[0].Name != "video.mp4" {
		t.Fatalf("without server orderby: %v %+v", err, items)
	}
}

func TestSearch(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g, "good")
	hits, err := d.Search(context.Background(), "memo", "", 10)
	if err != nil || len(hits) != 1 || hits[0].Name != "memo.docx" {
		t.Fatalf("search: %v %+v", err, hits)
	}
	if !g.sent("/drives/b%21personal/root/search(q='memo')") {
		t.Fatalf("search goes to the drive's root: %v", g.requests)
	}
	hits, err = d.Search(context.Background(), "it's a plan", siteDrive, 10)
	if err != nil || len(hits) != 0 || !g.sent("search(q='it%27%27s%20a%20plan')") {
		t.Fatalf("quotes are doubled and the query escaped: %v %v", err, g.requests[len(g.requests)-1])
	}
	if _, err := d.Search(context.Background(), "  ", "", 10); err == nil {
		t.Fatal("an empty query is refused")
	}
}

func TestFetchStaleTooLargeAndFolder(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g, "good")
	ctx := context.Background()
	items, _, _ := d.List(ctx, "", "Documents", 10, "")
	memo := items[0]
	c, err := d.Fetch(ctx, memo.ID, cloud.MaxDownload)
	if err != nil || string(c.Data) != "DOCX" || c.Exported || !strings.Contains(c.MIME, "wordprocessingml") {
		t.Fatalf("fetch: %v %+v", err, c)
	}
	if c.Item.Name != "memo.docx" || c.Item.ModifiedBy != "Holder" {
		t.Fatalf("metadata rides with the bytes: %+v", c.Item)
	}
	// An edit in the provider makes the listed id stale.
	g.touch("memo", "DOCX v2")
	if _, err := d.Fetch(ctx, memo.ID, cloud.MaxDownload); !errors.Is(err, cloud.ErrStale) {
		t.Fatalf("stale id: %v", err)
	}
	items, _, _ = d.List(ctx, "", "Documents", 10, "")
	if c, err := d.Fetch(ctx, items[0].ID, cloud.MaxDownload); err != nil || string(c.Data) != "DOCX v2" {
		t.Fatalf("a fresh id reads the new version: %v %q", err, c.Data)
	}
	// Past the bound the metadata is still served.
	c, err = d.Fetch(ctx, items[0].ID, 3)
	if !errors.Is(err, cloud.ErrTooLarge) || c.Item.Name != "memo.docx" {
		t.Fatalf("too large: %v %+v", err, c.Item)
	}
	root, _, _ := d.List(ctx, "", "", 10, "")
	if _, err := d.Fetch(ctx, root[1].ID, cloud.MaxDownload); !errors.Is(err, cloud.ErrIsFolder) {
		t.Fatalf("a folder: %v", err)
	}
	if _, err := d.Fetch(ctx, "not-an-id", cloud.MaxDownload); !errors.Is(err, cloud.ErrBadID) {
		t.Fatalf("bad id: %v", err)
	}
	g.remove("memo")
	if _, err := d.Fetch(ctx, items[0].ID, cloud.MaxDownload); !errors.Is(err, cloud.ErrNotFound) {
		t.Fatalf("removed: %v", err)
	}
}

func TestSaveIntoTheConnectorsFolderOnly(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g, "good")
	ctx := context.Background()
	it, err := d.Save(ctx, "", "notes.md", []byte("# hi"), "text/markdown")
	if err != nil {
		t.Fatal(err)
	}
	if it.Name != "notes.md" || it.Path != "/Privasys" || it.WebURL == "" || it.Drive != myDrive {
		t.Fatalf("saved: %+v", it)
	}
	// The folder was created at the root, with fail-on-conflict, and the
	// upload said so too.
	if !g.sent("POST /v1.0/drives/b%21personal/root/children") || !g.sent("conflictBehavior=fail") {
		t.Fatalf("creation: %v", g.requests)
	}
	// The same name again is suffixed, never replaced; a subfolder is made
	// under the connector's folder.
	it2, err := d.Save(ctx, "", "notes.md", []byte("# again"), "text/markdown")
	if err != nil || it2.Name != "notes (2).md" {
		t.Fatalf("suffix: %v %+v", err, it2)
	}
	it3, err := d.Save(ctx, "runs/today", "NOTES.MD", []byte("x"), "text/markdown")
	if err != nil || it3.Name != "NOTES.MD" || it3.Path != "/Privasys/runs/today" {
		t.Fatalf("subfolder: %v %+v", err, it3)
	}
	if _, err := d.Save(ctx, "runs/today", "notes", []byte("x"), "text/markdown"); err != nil {
		t.Fatal(err)
	}
	if g.byPath(myDrive, "/Privasys/runs/today/notes.md") == nil {
		t.Fatal("a name without an extension is a Markdown file")
	}
	// Nothing outside the folder, whatever the argument says.
	for _, bad := range []string{"../Documents", "/Documents", "Documents/../..", "a/./b", ".hidden", "a//b"} {
		if _, err := d.Save(ctx, bad, "x.md", []byte("x"), "text/markdown"); !errors.Is(err, cloud.ErrBadFolder) {
			t.Errorf("folder %q: %v", bad, err)
		}
	}
	for _, bad := range []string{"", "../x.md", "a/b.md", "x.exe", ".env", "x.docx"} {
		if _, err := d.Save(ctx, "", bad, []byte("x"), "text/plain"); !errors.Is(err, cloud.ErrBadName) {
			t.Errorf("name %q: %v", bad, err)
		}
	}
	for _, r := range g.requests {
		if (strings.HasPrefix(r, "PUT") || strings.HasPrefix(r, "POST")) && strings.Contains(r, "Documents") {
			t.Fatalf("a write reached outside the connector's folder: %s", r)
		}
	}
	if _, err := d.Save(ctx, "", "x.md", make([]byte, cloud.MaxSave+1), "text/markdown"); err == nil {
		t.Fatal("an oversized note is refused")
	}
}

func TestChanges(t *testing.T) {
	g := newFakeGraph(t)
	d := open(t, g, "good")
	ctx := context.Background()
	pollEvery = 10 * time.Millisecond
	t.Cleanup(func() { pollEvery = 20 * time.Second })

	// No cursor and no wait: a baseline from now, nothing reported.
	changes, cursor, err := d.Changes(ctx, "", 0)
	if err != nil || len(changes) != 0 || cursor == "" {
		t.Fatalf("baseline: %v %v %q", err, changes, cursor)
	}
	if !g.sent("root/delta?token=latest") {
		t.Fatalf("the baseline asks for latest: %v", g.requests)
	}
	// Quiet: the held call returns empty after the wait.
	changes, cursor2, err := d.Changes(ctx, cursor, 30*time.Millisecond)
	if err != nil || len(changes) != 0 || cursor2 == "" {
		t.Fatalf("quiet: %v %v", err, changes)
	}
	// A change during the wait is reported before it ends.
	go func() {
		time.Sleep(20 * time.Millisecond)
		g.touch("old", "newer")
		g.remove("big")
	}()
	start := time.Now()
	changes, cursor3, err := d.Changes(ctx, cursor2, 2*time.Second)
	if err != nil || len(changes) != 2 || time.Since(start) > time.Second {
		t.Fatalf("woken: %v %+v after %s", err, changes, time.Since(start))
	}
	kinds := map[string]string{}
	for _, c := range changes {
		kinds[c.Name] = c.Kind
	}
	if kinds["old.txt"] != "changed" || kinds["video.mp4"] != "removed" {
		t.Fatalf("kinds: %v", kinds)
	}
	// The changed id is fresh: it reads the new version.
	for _, c := range changes {
		if c.Kind == "changed" {
			if got, err := d.Fetch(ctx, c.ID, cloud.MaxDownload); err != nil || string(got.Data) != "newer" {
				t.Fatalf("the feed's id reads: %v %q", err, got.Data)
			}
		}
	}
	// A cursor from another host is not followed; a cursor Graph no
	// longer honours is a reset and a fresh cursor.
	if _, _, err := d.Changes(ctx, encodeCursor("https://evil.example/delta"), 0); err != nil || g.sent("evil") {
		t.Fatal("a foreign cursor is replaced with a baseline, never followed")
	}
	gone := encodeCursor(g.srv.URL + "/v1.0/drives/" + myDrive + "/root/delta?token=gone")
	changes, cursor4, err := d.Changes(ctx, gone, 10*time.Millisecond)
	if err != nil || len(changes) != 1 || changes[0].Kind != "reset" || cursor4 == gone || cursor4 == "" {
		t.Fatalf("gone: %v %+v %q", err, changes, cursor4)
	}
	if _, _, err := d.Changes(ctx, cursor4, 0); err != nil {
		t.Fatalf("the fresh cursor works: %v", err)
	}
	_ = cursor3
}
