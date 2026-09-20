// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package gdrive

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDrive is enough of the Drive API v3 for the driver: about, drives,
// files.list with the query shapes the driver writes, files.get with
// alt=media and export, changes with a start token, files.create for a
// folder and the multipart upload. It records every request so a test can
// say what was and was not sent.
type fakeDrive struct {
	srv *httptest.Server

	mu       sync.Mutex
	files    map[string]*dFile
	seq      int
	log      []change
	requests []string
	nextID   int
}

type dFile struct {
	id, name, mime, parent, drive string
	content                       []byte
	export                        map[string]string
	modified                      time.Time
	version                       int
	trashed                       bool
}

type change struct {
	seq     int
	fileID  string
	removed bool
}

const sharedDrive = "0AShared"

func newFakeDrive(t *testing.T) *fakeDrive {
	t.Helper()
	g := &fakeDrive{files: map[string]*dFile{}}
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	g.put(&dFile{id: "root", name: "My Drive", mime: mimeFolder})
	g.put(&dFile{id: "docs", name: "Documents", mime: mimeFolder, parent: "root", modified: base})
	g.put(&dFile{id: "gdoc", name: "Plan", mime: mimeDocument, parent: "docs", modified: base.Add(2 * time.Hour),
		export: map[string]string{"text/plain": "The plan\n\nStep one."}})
	g.put(&dFile{id: "sheet", name: "Budget", mime: mimeSpreadsheet, parent: "docs", modified: base.Add(time.Hour),
		export: map[string]string{"text/csv": "item,cost\nwidget,12"}})
	g.put(&dFile{id: "old", name: "old.txt", mime: "text/plain", parent: "docs", modified: base.Add(-48 * time.Hour), content: []byte("older")})
	g.put(&dFile{id: "form", name: "Survey", mime: "application/vnd.google-apps.form", parent: "root", modified: base})
	g.put(&dFile{id: sharedDrive, name: "Team", mime: mimeFolder, drive: sharedDrive})
	g.put(&dFile{id: "tplan", name: "plan.md", mime: "text/markdown", parent: sharedDrive, drive: sharedDrive, modified: base, content: []byte("# team plan")})
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.serve)
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeDrive) put(f *dFile) {
	g.seq++
	if f.version == 0 {
		f.version = 1
	}
	g.files[f.id] = f
	g.log = append(g.log, change{seq: g.seq, fileID: f.id})
}

func (g *fakeDrive) json(f *dFile) map[string]any {
	out := map[string]any{
		"id": f.id, "name": f.name, "mimeType": f.mime, "modifiedTime": f.modified.Format(time.RFC3339),
		"version": strconv.Itoa(f.version), "webViewLink": "https://drive.google.com/file/d/" + f.id, "trashed": f.trashed,
		"lastModifyingUser": map[string]any{"displayName": "Holder"},
	}
	if f.content != nil {
		out["size"] = strconv.Itoa(len(f.content))
	}
	if f.parent != "" {
		out["parents"] = []string{f.parent}
	}
	if f.drive != "" {
		out["driveId"] = f.drive
	}
	return out
}

func (g *fakeDrive) fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": status, "message": msg}})
}

func (g *fakeDrive) ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

var (
	qParent   = regexp.MustCompile(`'((?:[^'\\]|\\.)*)' in parents`)
	qName     = regexp.MustCompile(`name = '((?:[^'\\]|\\.)*)'`)
	qMime     = regexp.MustCompile(`mimeType = '((?:[^'\\]|\\.)*)'`)
	qFullText = regexp.MustCompile(`fullText contains '((?:[^'\\]|\\.)*)'`)
)

func unq(s string) string {
	s = strings.ReplaceAll(s, `\'`, `'`)
	return strings.ReplaceAll(s, `\\`, `\`)
}

func (g *fakeDrive) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, r.Method+" "+r.URL.RequestURI())
	if r.Header.Get("Authorization") != "Bearer good" {
		g.fail(w, http.StatusUnauthorized, "Invalid Credentials")
		return
	}
	q := r.URL.Query()
	p := r.URL.Path
	switch {
	case p == "/drive/v3/about":
		g.ok(w, map[string]any{"user": map[string]any{"displayName": "Holder Example", "emailAddress": "Holder@Gmail.com"}, "storageQuota": map[string]any{"limit": "1"}})
	case p == "/drive/v3/drives":
		g.ok(w, map[string]any{"drives": []map[string]any{{"id": sharedDrive, "name": "Team"}}})
	case p == "/drive/v3/changes/startPageToken":
		g.ok(w, map[string]any{"startPageToken": strconv.Itoa(g.seq)})
	case p == "/drive/v3/changes":
		g.serveChanges(w, q)
	case p == "/drive/v3/files" && r.Method == http.MethodGet:
		g.serveList(w, q)
	case p == "/drive/v3/files" && r.Method == http.MethodPost:
		var body struct {
			Name     string   `json:"name"`
			MimeType string   `json:"mimeType"`
			Parents  []string `json:"parents"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.MimeType != mimeFolder || len(body.Parents) != 1 {
			g.fail(w, http.StatusBadRequest, "only a folder with one parent is created here")
			return
		}
		f := g.create(body.Name, body.MimeType, body.Parents[0], nil)
		g.ok(w, g.json(f))
	case p == "/upload/drive/v3/files" && r.Method == http.MethodPost:
		g.serveUpload(w, r, q)
	case strings.HasPrefix(p, "/drive/v3/files/"):
		rest := strings.TrimPrefix(p, "/drive/v3/files/")
		id, action, _ := strings.Cut(rest, "/")
		f := g.files[id]
		if f == nil {
			g.fail(w, http.StatusNotFound, "File not found: "+id)
			return
		}
		switch {
		case action == "export":
			text, ok := f.export[q.Get("mimeType")]
			if !ok {
				g.fail(w, http.StatusBadRequest, "Export only supports Docs Editors files")
				return
			}
			w.Header().Set("Content-Type", q.Get("mimeType"))
			_, _ = io.WriteString(w, text)
		case action == "" && q.Get("alt") == "media":
			if f.content == nil {
				g.fail(w, http.StatusForbidden, "Only files with binary content can be downloaded")
				return
			}
			w.Header().Set("Content-Type", f.mime)
			_, _ = w.Write(f.content)
		case action == "":
			g.ok(w, g.json(f))
		default:
			g.fail(w, http.StatusMethodNotAllowed, r.Method+" "+action+" is not something this driver should send")
		}
	default:
		g.fail(w, http.StatusNotFound, "no route "+p)
	}
}

func (g *fakeDrive) create(name, mimeType, parent string, content []byte) *dFile {
	g.nextID++
	f := &dFile{id: fmt.Sprintf("new%d", g.nextID), name: name, mime: mimeType, parent: parent, content: content, modified: time.Now().UTC()}
	if pf := g.files[parent]; pf != nil {
		f.drive = pf.drive
	}
	g.put(f)
	return f
}

func (g *fakeDrive) serveList(w http.ResponseWriter, q url.Values) {
	expr := q.Get("q")
	if !strings.Contains(expr, "trashed = false") {
		g.fail(w, http.StatusBadRequest, "every listing must exclude the bin")
		return
	}
	var hits []*dFile
	for _, f := range g.files {
		if f.trashed || f.parent == "" {
			continue
		}
		if m := qParent.FindStringSubmatch(expr); m != nil && f.parent != unq(m[1]) {
			continue
		}
		if m := qName.FindStringSubmatch(expr); m != nil && f.name != unq(m[1]) {
			continue
		}
		if m := qMime.FindStringSubmatch(expr); m != nil && f.mime != unq(m[1]) {
			continue
		}
		if m := qFullText.FindStringSubmatch(expr); m != nil {
			term := strings.ToLower(unq(m[1]))
			hay := strings.ToLower(f.name + " " + string(f.content))
			for _, e := range f.export {
				hay += " " + strings.ToLower(e)
			}
			if !strings.Contains(hay, term) {
				continue
			}
		}
		if q.Get("corpora") == "drive" && f.drive != q.Get("driveId") {
			continue
		}
		if q.Get("corpora") == "" && f.drive != "" {
			continue
		}
		hits = append(hits, f)
	}
	// By id first so a tie on the time is deterministic, as a real server
	// is in its own way.
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].id < hits[j].id })
	if q.Get("orderBy") == "modifiedTime desc" {
		sort.SliceStable(hits, func(i, j int) bool { return hits[i].modified.After(hits[j].modified) })
	}
	size, _ := strconv.Atoi(q.Get("pageSize"))
	if size <= 0 {
		size = 100
	}
	start, _ := strconv.Atoi(q.Get("pageToken"))
	if start > len(hits) {
		start = len(hits)
	}
	end := start + size
	if end > len(hits) {
		end = len(hits)
	}
	out := map[string]any{"files": g.jsonAll(hits[start:end])}
	if end < len(hits) {
		out["nextPageToken"] = strconv.Itoa(end)
	}
	g.ok(w, out)
}

func (g *fakeDrive) jsonAll(fs []*dFile) []map[string]any {
	out := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		out = append(out, g.json(f))
	}
	return out
}

func (g *fakeDrive) serveUpload(w http.ResponseWriter, r *http.Request, q url.Values) {
	if q.Get("uploadType") != "multipart" {
		g.fail(w, http.StatusBadRequest, "not a multipart upload")
		return
	}
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		g.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	metaPart, err := mr.NextPart()
	if err != nil {
		g.fail(w, http.StatusBadRequest, "no metadata part")
		return
	}
	var meta struct {
		Name     string   `json:"name"`
		Parents  []string `json:"parents"`
		MimeType string   `json:"mimeType"`
	}
	_ = json.NewDecoder(metaPart).Decode(&meta)
	mediaPart, err := mr.NextPart()
	if err != nil {
		g.fail(w, http.StatusBadRequest, "no media part")
		return
	}
	content, _ := io.ReadAll(mediaPart)
	if len(meta.Parents) != 1 || g.files[meta.Parents[0]] == nil {
		g.fail(w, http.StatusBadRequest, "an upload must name one existing parent")
		return
	}
	f := g.create(meta.Name, meta.MimeType, meta.Parents[0], content)
	g.ok(w, g.json(f))
}

func (g *fakeDrive) serveChanges(w http.ResponseWriter, q url.Values) {
	since, err := strconv.Atoi(q.Get("pageToken"))
	if err != nil {
		g.fail(w, http.StatusBadRequest, "Invalid Value for pageToken")
		return
	}
	var out []map[string]any
	for _, c := range g.log {
		if c.seq <= since {
			continue
		}
		f := g.files[c.fileID]
		entry := map[string]any{"changeType": "file", "fileId": c.fileID, "removed": c.removed}
		if !c.removed {
			entry["file"] = g.json(f)
		}
		out = append(out, entry)
	}
	g.ok(w, map[string]any{"changes": out, "newStartPageToken": strconv.Itoa(g.seq)})
}

// touch edits a file's content, as the holder would in the provider.
func (g *fakeDrive) touch(id, content string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f := g.files[id]
	f.content = []byte(content)
	f.version++
	f.modified = time.Now().UTC()
	g.seq++
	g.log = append(g.log, change{seq: g.seq, fileID: id})
}

// remove deletes a file outright.
func (g *fakeDrive) remove(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.files, id)
	g.seq++
	g.log = append(g.log, change{seq: g.seq, fileID: id, removed: true})
}

func (g *fakeDrive) sent(substr string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range g.requests {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

// byName finds the file of a name under a parent, for assertions.
func (g *fakeDrive) byName(parent, name string) *dFile {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, f := range g.files {
		if f.parent == parent && f.name == name && !f.trashed {
			return f
		}
	}
	return nil
}
