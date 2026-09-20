// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGraph is enough of Microsoft Graph for the driver: one personal
// drive and one SharePoint library, items in a tree, the content route's
// redirect, a delta log, folder creation and a small upload. It records
// every request path so a test can say what was and was not sent.
type fakeGraph struct {
	srv *httptest.Server

	mu       sync.Mutex
	items    map[string]*gItem
	seq      int
	requests []string
	// noOrderBy makes the children route refuse $orderby, as some
	// libraries do.
	noOrderBy bool
	// personal makes the SharePoint legs answer 400, as a personal account
	// does.
	personal bool
	nextID   int
}

type gItem struct {
	id, drive, parent, name string
	folder                  bool
	content                 []byte
	mime                    string
	modified                time.Time
	version                 int
	seq                     int
	deleted                 bool
}

const (
	myDrive   = "b!personal"
	siteDrive = "b!site-docs"
)

func newFakeGraph(t *testing.T) *fakeGraph {
	t.Helper()
	g := &fakeGraph{items: map[string]*gItem{}}
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	g.add(&gItem{id: "root", drive: myDrive, folder: true, name: "root"})
	g.add(&gItem{id: "docs", drive: myDrive, parent: "root", folder: true, name: "Documents", modified: base})
	g.add(&gItem{id: "old", drive: myDrive, parent: "docs", name: "old.txt", content: []byte("older"), mime: "text/plain", modified: base.Add(-48 * time.Hour)})
	g.add(&gItem{id: "memo", drive: myDrive, parent: "docs", name: "memo.docx", content: []byte("DOCX"), mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", modified: base.Add(2 * time.Hour)})
	g.add(&gItem{id: "big", drive: myDrive, parent: "root", name: "video.mp4", content: []byte("MP4"), mime: "video/mp4", modified: base.Add(time.Hour)})
	g.items["big"].content = nil // the size is set by the test that needs it
	g.add(&gItem{id: "sroot", drive: siteDrive, folder: true, name: "root"})
	g.add(&gItem{id: "plan", drive: siteDrive, parent: "sroot", name: "plan.md", content: []byte("# Plan\ncode: 123456"), mime: "text/markdown", modified: base})
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.serve)
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGraph) add(it *gItem) {
	g.seq++
	it.seq = g.seq
	if it.version == 0 {
		it.version = 1
	}
	g.items[it.id] = it
}

func (g *fakeGraph) etag(it *gItem) string { return fmt.Sprintf(`"{%s},%d"`, it.id, it.version) }

func (g *fakeGraph) path(it *gItem) string {
	if it.parent == "" {
		return "/drive/root:"
	}
	p := g.items[it.parent]
	if p.parent == "" {
		return "/drive/root:"
	}
	return g.path(p) + "/" + p.name
}

func (g *fakeGraph) json(it *gItem) map[string]any {
	out := map[string]any{
		"id": it.id, "name": it.name, "eTag": g.etag(it), "size": len(it.content),
		"webUrl": "https://onedrive.example/" + it.id, "lastModifiedDateTime": it.modified.Format(time.RFC3339),
		"parentReference": map[string]any{"driveId": it.drive, "path": g.path(it)},
		"lastModifiedBy":  map[string]any{"user": map[string]any{"displayName": "Holder"}},
	}
	if it.folder {
		n := 0
		for _, c := range g.items {
			if c.parent == it.id && !c.deleted {
				n++
			}
		}
		out["folder"] = map[string]any{"childCount": n}
	} else {
		out["file"] = map[string]any{"mimeType": it.mime}
	}
	if it.parent == "" {
		out["root"] = map[string]any{}
	}
	if it.deleted {
		out["deleted"] = map[string]any{"state": "deleted"}
	}
	return out
}

func (g *fakeGraph) children(parent string) []*gItem {
	var out []*gItem
	for _, it := range g.items {
		if it.parent == parent && !it.deleted {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// byPath finds an item by a "/a/b" path under a drive's root.
func (g *fakeGraph) byPath(drive, p string) *gItem {
	cur := g.rootOf(drive)
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if seg == "" {
			continue
		}
		seg, _ = url.PathUnescape(seg)
		var next *gItem
		for _, c := range g.children(cur.id) {
			if strings.EqualFold(c.name, seg) {
				next = c
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

func (g *fakeGraph) rootOf(drive string) *gItem {
	for _, it := range g.items {
		if it.drive == drive && it.parent == "" {
			return it
		}
	}
	return nil
}

func (g *fakeGraph) fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (g *fakeGraph) ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// serve parses Graph's URL shapes by hand: the root:/path: form has colons
// no mux pattern takes.
func (g *fakeGraph) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, r.Method+" "+r.URL.RequestURI())
	if strings.HasPrefix(r.URL.Path, "/dl/") {
		// The pre-authenticated download: no bearer expected, and none
		// should have been forwarded.
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "the bearer was forwarded to the download host", http.StatusBadRequest)
			return
		}
		it := g.items[strings.TrimPrefix(r.URL.Path, "/dl/")]
		w.Header().Set("Content-Type", it.mime)
		_, _ = w.Write(it.content)
		return
	}
	if r.Header.Get("Authorization") != "Bearer good" {
		g.fail(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token has expired or is not yet valid.")
		return
	}
	q := r.URL.Query()
	p := strings.TrimPrefix(r.URL.Path, "/v1.0")
	switch {
	case p == "/me":
		g.ok(w, map[string]any{"displayName": "Holder Example", "mail": "Holder@Example.org", "userPrincipalName": "holder@example.org"})
	case p == "/me/drive":
		g.ok(w, map[string]any{"id": myDrive, "driveType": "business", "name": "OneDrive", "webUrl": "https://onedrive.example/"})
	case p == "/me/followedSites" || p == "/sites":
		if g.personal {
			g.fail(w, http.StatusBadRequest, "invalidRequest", "not supported for personal accounts")
			return
		}
		g.ok(w, map[string]any{"value": []map[string]any{{"id": "site-1", "displayName": "Team Site", "name": "team"}}})
	case p == "/sites/site-1/drives":
		g.ok(w, map[string]any{"value": []map[string]any{{"id": siteDrive, "driveType": "documentLibrary", "name": "Documents", "webUrl": "https://sp.example/team/Shared%20Documents"}}})
	case p == "/me/insights/used":
		g.ok(w, map[string]any{"value": []map[string]any{{"resourceReference": map[string]any{"id": "drives/b!recent/items/x1"}}}})
	case p == "/drives/b!recent":
		g.ok(w, map[string]any{"id": "b!recent", "driveType": "documentLibrary", "name": "Recent Library", "webUrl": "https://sp.example/other"})
	case strings.HasPrefix(p, "/drives/"):
		g.serveDrive(w, r, strings.TrimPrefix(p, "/drives/"), q)
	default:
		g.fail(w, http.StatusNotFound, "itemNotFound", "no route "+p)
	}
}

func (g *fakeGraph) serveDrive(w http.ResponseWriter, r *http.Request, rest string, q url.Values) {
	drive, rest, _ := strings.Cut(rest, "/")
	drive, _ = url.PathUnescape(drive)
	if g.rootOf(drive) == nil {
		g.fail(w, http.StatusNotFound, "itemNotFound", "no such drive")
		return
	}
	// Resolve the item the path addresses, and what is asked of it.
	var it *gItem
	var action string
	switch {
	case strings.HasPrefix(rest, "root/delta"):
		g.serveDelta(w, drive, q)
		return
	case strings.HasPrefix(rest, "root/search("):
		g.serveSearch(w, drive, rest, q)
		return
	case rest == "root/children":
		it, action = g.rootOf(drive), "children"
	case strings.HasPrefix(rest, "root:/"):
		path, after, _ := strings.Cut(strings.TrimPrefix(rest, "root:/"), ":")
		it, action = g.byPath(drive, path), strings.TrimPrefix(after, "/")
		if it == nil && r.Method == http.MethodGet && action == "" {
			g.fail(w, http.StatusNotFound, "itemNotFound", "no such path")
			return
		}
	case strings.HasPrefix(rest, "items/"):
		// items/{id}/children, items/{id}, items/{id}/content, and the
		// path-addressed forms items/{id}:/name and items/{id}:/name:/content.
		rest = strings.TrimPrefix(rest, "items/")
		var id, after, child string
		if i := strings.Index(rest, ":"); i >= 0 && (strings.Index(rest, "/") < 0 || i < strings.Index(rest, "/")) {
			id = rest[:i]
			child = strings.TrimPrefix(rest[i:], ":/")
			if j := strings.Index(child, ":"); j >= 0 {
				after = strings.TrimPrefix(child[j:], ":/")
				child = child[:j]
			}
			child, _ = url.PathUnescape(child)
		} else {
			id, after, _ = strings.Cut(rest, "/")
		}
		id, _ = url.PathUnescape(id)
		it = g.items[id]
		if it == nil || it.deleted {
			g.fail(w, http.StatusNotFound, "itemNotFound", "no such item")
			return
		}
		action = after
		if child != "" {
			if after == "content" && r.Method == http.MethodPut {
				g.upload(w, r, it, child, q)
				return
			}
			var found *gItem
			for _, c := range g.children(it.id) {
				if strings.EqualFold(c.name, child) {
					found = c
				}
			}
			if found == nil {
				g.fail(w, http.StatusNotFound, "itemNotFound", "no such child")
				return
			}
			g.ok(w, g.json(found))
			return
		}
	default:
		g.fail(w, http.StatusNotFound, "itemNotFound", "no route")
		return
	}
	if it == nil {
		g.fail(w, http.StatusNotFound, "itemNotFound", "no such item")
		return
	}
	switch {
	case action == "children" && r.Method == http.MethodGet:
		if q.Get("$orderby") != "" && g.noOrderBy {
			g.fail(w, http.StatusBadRequest, "invalidRequest", "orderby not supported")
			return
		}
		kids := g.children(it.id)
		if q.Get("$orderby") != "" {
			sort.SliceStable(kids, func(i, j int) bool { return kids[i].modified.After(kids[j].modified) })
		}
		top, _ := strconv.Atoi(q.Get("$top"))
		if top <= 0 {
			top = 200
		}
		skip, _ := strconv.Atoi(q.Get("$skiptoken"))
		if skip > len(kids) {
			skip = len(kids)
		}
		end := skip + top
		if end > len(kids) {
			end = len(kids)
		}
		out := map[string]any{"value": g.jsonAll(kids[skip:end])}
		if end < len(kids) {
			next := *r.URL
			nq := next.Query()
			nq.Set("$skiptoken", strconv.Itoa(end))
			next.RawQuery = nq.Encode()
			out["@odata.nextLink"] = g.srv.URL + next.String()
		}
		g.ok(w, out)
	case action == "children" && r.Method == http.MethodPost:
		var body struct {
			Name     string          `json:"name"`
			Folder   json.RawMessage `json:"folder"`
			Conflict string          `json:"@microsoft.graph.conflictBehavior"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Folder == nil || body.Conflict != "fail" {
			g.fail(w, http.StatusBadRequest, "invalidRequest", "only a folder with conflictBehavior=fail is created here")
			return
		}
		for _, c := range g.children(it.id) {
			if strings.EqualFold(c.name, body.Name) {
				g.fail(w, http.StatusConflict, "nameAlreadyExists", "exists")
				return
			}
		}
		g.nextID++
		n := &gItem{id: fmt.Sprintf("new%d", g.nextID), drive: it.drive, parent: it.id, name: body.Name, folder: true, modified: time.Now().UTC()}
		g.add(n)
		w.WriteHeader(http.StatusCreated)
		g.ok(w, g.json(n))
	case action == "" && r.Method == http.MethodGet:
		g.ok(w, g.json(it))
	case action == "content" && r.Method == http.MethodGet:
		http.Redirect(w, r, g.srv.URL+"/dl/"+it.id, http.StatusFound)
	default:
		g.fail(w, http.StatusMethodNotAllowed, "notAllowed", r.Method+" "+action+" is not something this driver should send")
	}
}

func (g *fakeGraph) jsonAll(items []*gItem) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, g.json(it))
	}
	return out
}

func (g *fakeGraph) upload(w http.ResponseWriter, r *http.Request, parent *gItem, name string, q url.Values) {
	if q.Get("@microsoft.graph.conflictBehavior") != "fail" {
		g.fail(w, http.StatusBadRequest, "invalidRequest", "an upload must say conflictBehavior=fail")
		return
	}
	for _, c := range g.children(parent.id) {
		if strings.EqualFold(c.name, name) {
			g.fail(w, http.StatusConflict, "nameAlreadyExists", "exists")
			return
		}
	}
	body, _ := io.ReadAll(r.Body)
	g.nextID++
	n := &gItem{id: fmt.Sprintf("new%d", g.nextID), drive: parent.drive, parent: parent.id, name: name, content: body, mime: r.Header.Get("Content-Type"), modified: time.Now().UTC()}
	g.add(n)
	w.WriteHeader(http.StatusCreated)
	g.ok(w, g.json(n))
}

func (g *fakeGraph) serveSearch(w http.ResponseWriter, drive, rest string, q url.Values) {
	// root/search(q='term')
	term := strings.TrimSuffix(strings.TrimPrefix(rest, "root/search(q='"), "')")
	term, _ = url.PathUnescape(term)
	term = strings.ToLower(strings.ReplaceAll(term, "''", "'"))
	var hits []*gItem
	for _, it := range g.items {
		if it.drive == drive && !it.deleted && it.parent != "" && (strings.Contains(strings.ToLower(it.name), term) || strings.Contains(strings.ToLower(string(it.content)), term)) {
			hits = append(hits, it)
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].id < hits[j].id })
	if top, _ := strconv.Atoi(q.Get("$top")); top > 0 && len(hits) > top {
		hits = hits[:top]
	}
	g.ok(w, map[string]any{"value": g.jsonAll(hits)})
}

func (g *fakeGraph) serveDelta(w http.ResponseWriter, drive string, q url.Values) {
	token := q.Get("token")
	if token == "gone" {
		g.fail(w, http.StatusGone, "resyncRequired", "the token is too old")
		return
	}
	since := g.seq
	if token != "latest" {
		since, _ = strconv.Atoi(token)
	}
	var out []*gItem
	for _, it := range g.items {
		if it.drive == drive && it.seq > since {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	g.ok(w, map[string]any{
		"value":            g.jsonAll(out),
		"@odata.deltaLink": g.srv.URL + "/v1.0/drives/" + drive + "/root/delta?token=" + strconv.Itoa(g.seq),
	})
}

// touch changes an item's content, as an edit in the provider would.
func (g *fakeGraph) touch(id string, content string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	it := g.items[id]
	it.content = []byte(content)
	it.version++
	it.modified = time.Now().UTC()
	g.seq++
	it.seq = g.seq
}

// remove deletes an item, as the holder would in the provider.
func (g *fakeGraph) remove(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	it := g.items[id]
	it.deleted = true
	g.seq++
	it.seq = g.seq
}

func (g *fakeGraph) sent(substr string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range g.requests {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}
