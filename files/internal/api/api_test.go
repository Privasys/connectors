// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/connectors/files/internal/cloud"
	"github.com/Privasys/connectors/files/internal/store"
	"github.com/Privasys/connectors/sdk/caller"
	"github.com/Privasys/connectors/sdk/grant"
	"github.com/Privasys/connectors/sdk/holder"
	"github.com/Privasys/connectors/sdk/provider"
)

// fakeMX is the DNS the tests see: example.org at Microsoft 365,
// workspace.example at Google Workspace, self.example hosted by itself, and
// every other domain unknown.
func fakeMX(_ context.Context, domain string) ([]*net.MX, error) {
	switch domain {
	case "example.org":
		return []*net.MX{{Host: "example-org.mail.protection.outlook.com."}}, nil
	case "workspace.example":
		return []*net.MX{{Host: "aspmx.l.google.com."}}, nil
	case "self.example":
		return []*net.MX{{Host: "mail.self.example."}}, nil
	}
	return nil, errors.New("no such domain")
}

const testApp = "590ebdc31b63401fbbb822d5f3886c5e"

var day = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

// fakeDriver is a file store with a few files: a Word document, a Google
// Doc read through export, a text file with a one-time code in it, an
// image, and a folder. It records what Save was asked and refuses nothing
// the domain helpers would not, so the api's own checks are what is tested.
type fakeDriver struct {
	provider string
	user     string
	token    cloud.TokenFunc
	saved    []string
	names    map[string]bool
	closed   bool
}

func docxOf(paragraphs ...string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("word/document.xml")
	fmt.Fprint(w, `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	for _, p := range paragraphs {
		fmt.Fprintf(w, `<w:p><w:r><w:t>%s</w:t></w:r></w:p>`, p)
	}
	fmt.Fprint(w, `</w:body></w:document>`)
	_ = zw.Close()
	return buf.Bytes()
}

var fakeFiles = map[string]cloud.Content{
	"memo": {Item: cloud.Item{Name: "memo.docx", Size: 100, MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Modified: day, Drive: "d1"},
		Data: docxOf("Quarterly memo", "Your verification code is 483920", "The end"), MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	"gdoc":  {Item: cloud.Item{Name: "Plan", Native: "document", Modified: day, Drive: "root"}, Data: []byte("The plan\nStep one."), MIME: "text/plain", Exported: true},
	"sheet": {Item: cloud.Item{Name: "Budget", Native: "spreadsheet", Modified: day, Drive: "root"}, Data: []byte("a,b\n1,2"), MIME: "text/csv", Exported: true},
	"notes": {Item: cloud.Item{Name: "notes.txt", Size: 7000, MIME: "text/plain", Modified: day, Drive: "d1"}, Data: []byte(strings.Repeat("line of text\n", 500)), MIME: "text/plain"},
	"photo": {Item: cloud.Item{Name: "photo.jpg", Size: 5, MIME: "image/jpeg", Modified: day, Drive: "d1"}, Data: []byte("JPEG!"), MIME: "image/jpeg"},
	"bad":   {Item: cloud.Item{Name: "broken.docx", Size: 3, Modified: day, Drive: "d1"}, Data: []byte("PK!"), MIME: "application/octet-stream"},
}

func fakeID(key string) string { return cloud.EncodeID("d1", key, "v1") }

func (f *fakeDriver) Account(context.Context) (cloud.Account, error) {
	return cloud.Account{Provider: f.provider, User: f.user, Name: "Holder", DriveID: "d1", DriveType: "business"}, nil
}
func (f *fakeDriver) Drives(context.Context) ([]cloud.Drive, error) {
	return []cloud.Drive{{ID: "d1", Name: "OneDrive", Kind: "personal"}, {ID: "d2", Name: "Docs", Kind: "sharepoint", Site: "Team"}}, nil
}
func (f *fakeDriver) List(_ context.Context, drive, folder string, limit int, page string) ([]cloud.Item, string, error) {
	if folder == "missing" {
		return nil, "", cloud.ErrNotFound
	}
	var out []cloud.Item
	for k, c := range fakeFiles {
		it := c.Item
		it.ID = fakeID(k)
		out = append(out, it)
	}
	out = append(out, cloud.Item{ID: fakeID("folder"), Name: "Reports", Folder: true, Drive: "d1"})
	if limit > 0 && limit < len(out) && page == "" {
		return out[:limit], "next", nil
	}
	return out, "", nil
}
func (f *fakeDriver) Search(_ context.Context, query, drive string, limit int) ([]cloud.Item, error) {
	var out []cloud.Item
	for k, c := range fakeFiles {
		if strings.Contains(strings.ToLower(c.Item.Name), strings.ToLower(query)) {
			it := c.Item
			it.ID = fakeID(k)
			out = append(out, it)
		}
	}
	return out, nil
}
func (f *fakeDriver) Fetch(_ context.Context, id string, max int64) (cloud.Content, error) {
	_, key, etag, err := cloud.DecodeID(id)
	if err != nil {
		return cloud.Content{}, err
	}
	if etag == "stale" {
		return cloud.Content{}, cloud.ErrStale
	}
	if key == "folder" {
		return cloud.Content{Item: cloud.Item{Name: "Reports", Folder: true}}, cloud.ErrIsFolder
	}
	c, ok := fakeFiles[key]
	if !ok {
		return cloud.Content{}, cloud.ErrNotFound
	}
	c.Item.ID = id
	if int64(len(c.Data)) > max {
		return cloud.Content{Item: c.Item}, cloud.ErrTooLarge
	}
	return c, nil
}
func (f *fakeDriver) Changes(context.Context, string, time.Duration) ([]cloud.Change, string, error) {
	return []cloud.Change{{ID: fakeID("memo"), Kind: "changed", Name: "memo.docx"}}, "cur-1", nil
}
func (f *fakeDriver) Save(_ context.Context, folder, name string, content []byte, mime string) (cloud.Item, error) {
	if _, err := cloud.CleanFolder(folder); err != nil {
		return cloud.Item{}, err
	}
	if f.names == nil {
		f.names = map[string]bool{}
	}
	name = cloud.UniqueName(name, func(n string) bool { return f.names[folder+"/"+n] })
	f.names[folder+"/"+name] = true
	f.saved = append(f.saved, folder+"/"+name+":"+mime+":"+string(content))
	return cloud.Item{ID: fakeID("new"), Name: name, Path: "/" + cloud.Folder + "/" + folder, WebURL: "https://example/new", Drive: "d1"}, nil
}
func (f *fakeDriver) Close() error { f.closed = true; return nil }

// rig is a connector whose accounts open onto fake drivers. A bearer is
// asked for and recorded; "bad-token" is the provider refusing it.
type rig struct {
	s       *Server
	drivers []*fakeDriver
	bearers []string
	// identity is the address the fake provider says signed in.
	identity string
}

func newRig(t *testing.T, requireGrant bool) *rig {
	t.Helper()
	r := &rig{s: New(store.NewMemory(), grant.NewMemory(), requireGrant), identity: "me@example.org"}
	r.s.who = &provider.Resolver{LookupMX: fakeMX}
	r.s.open = func(ctx context.Context, provider string, tok cloud.TokenFunc) (cloud.Driver, error) {
		bearer, err := tok(ctx)
		if err != nil {
			return nil, err
		}
		r.bearers = append(r.bearers, bearer)
		if bearer == "bad-token" {
			return nil, cloud.ErrLogin
		}
		d := &fakeDriver{provider: provider, user: r.identity, token: tok}
		r.drivers = append(r.drivers, d)
		return d, nil
	}
	return r
}

func (r *rig) do(method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Host = "files.apps.example"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.s.Routes().ServeHTTP(w, req)
	return w
}

func asUser(sub string) map[string]string {
	return map[string]string{caller.SubjectHeader: sub, caller.PeerAppHeader: testApp}
}

func asHolder(sub string) map[string]string { return map[string]string{holder.RelaySubjectHeader: sub} }

func mintBody(setup map[string]any, perms ...string) string {
	if len(perms) == 0 {
		perms = []string{"read", "write"}
	}
	req := map[string]any{
		"nonce": "n-1", "subject_app_id": testApp, "kind": cloud.Kind,
		"permissions": perms, "expires_unix": time.Now().Add(24 * time.Hour).Unix(),
	}
	if setup != nil {
		req["setup"] = setup
	}
	b, _ := json.Marshal(req)
	return string(b)
}

// connect puts a proven account in memory directly, as a mint with a kept
// token would, and mints the capability over it.
func (r *rig) connect(t *testing.T, sub string, perms ...string) {
	t.Helper()
	_ = r.s.credStore().Put(context.Background(), sub, store.Account{
		Provider: cloud.ProviderMicrosoft, User: sub + "@example.org", DriveID: "d1", LinkedAt: time.Now(),
		RefreshToken: "rt-1", AccessToken: "at-1", Expiry: time.Now().Add(time.Hour),
	})
	w := r.do(http.MethodPost, "/v1/capabilities", asHolder(sub), mintBody(nil, perms...))
	if w.Code != http.StatusOK {
		t.Fatalf("mint: %d %s", w.Code, w.Body)
	}
}

func (r *rig) call(t *testing.T, sub, tool, body string) *httptest.ResponseRecorder {
	t.Helper()
	return r.do(http.MethodPost, "/tools/"+tool, asUser(sub), body)
}

func decode(t *testing.T, w *httptest.ResponseRecorder, into any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), into); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, w.Body)
	}
}

// ---------------------------------------------------------------- tools

func TestListDrivesAndFolder(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	w := r.call(t, "u1", "list_drives", `{}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"kind":"sharepoint"`) {
		t.Fatalf("drives: %d %s", w.Code, w.Body)
	}
	w = r.call(t, "u1", "list_folder", `{"limit":2}`)
	var got struct {
		Items []cloud.Item `json:"items"`
		Page  string       `json:"page"`
	}
	decode(t, w, &got)
	if w.Code != http.StatusOK || len(got.Items) != 2 || got.Page != "next" {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "list_folder", `{"path_or_id":"missing"}`); w.Code != http.StatusNotFound {
		t.Fatalf("a missing folder is 404: %d %s", w.Code, w.Body)
	}
	w = r.call(t, "u1", "search", `{"query":"memo"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "memo.docx") {
		t.Fatalf("search: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "search", `{"query":" "}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an empty query: %d", w.Code)
	}
}

func TestGetFileExtractsExportsPagesAndRedacts(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	var got struct {
		File       cloud.Item `json:"file"`
		Kind       string     `json:"kind"`
		Text       string     `json:"text"`
		Offset     int        `json:"offset"`
		NextOffset *int       `json:"next_offset"`
		TextBytes  int        `json:"text_bytes"`
		Redactions int        `json:"redactions"`
		Note       string     `json:"note"`
	}
	w := r.call(t, "u1", "get_file", `{"id":"`+fakeID("memo")+`"}`)
	decode(t, w, &got)
	if w.Code != http.StatusOK || got.Kind != "docx" || got.File.Name != "memo.docx" {
		t.Fatalf("docx: %d %s", w.Code, w.Body)
	}
	if got.Text != "Quarterly memo\nYour verification code is [one-time code removed]\nThe end" || got.Redactions != 1 {
		t.Fatalf("docx text, redacted: %q %d", got.Text, got.Redactions)
	}
	w = r.call(t, "u1", "get_file", `{"id":"`+fakeID("gdoc")+`"}`)
	decode(t, w, &got)
	if w.Code != http.StatusOK || got.Kind != "export" || got.Text != "The plan\nStep one." || got.File.Native != "document" {
		t.Fatalf("google doc: %d %s", w.Code, w.Body)
	}
	w = r.call(t, "u1", "get_file", `{"id":"`+fakeID("sheet")+`"}`)
	decode(t, w, &got)
	if w.Code != http.StatusOK || got.Kind != "export-csv" || got.Text != "a,b\n1,2" {
		t.Fatalf("google sheet: %d %s", w.Code, w.Body)
	}
	// An image is metadata and a note; a folder likewise; a broken docx too.
	for _, key := range []string{"photo", "bad", "folder"} {
		w = r.call(t, "u1", "get_file", `{"id":"`+fakeID(key)+`"}`)
		got.Text, got.Note = "", ""
		decode(t, w, &got)
		if w.Code != http.StatusOK || got.Note == "" || got.Text != "" {
			t.Fatalf("%s: metadata only with a note: %d %s", key, w.Code, w.Body)
		}
	}
	// A stale id is 409, a bad one 400, a gone one 404.
	if w := r.call(t, "u1", "get_file", `{"id":"`+cloud.EncodeID("d1", "memo", "stale")+`"}`); w.Code != http.StatusConflict {
		t.Fatalf("stale: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "get_file", `{"id":"nope"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad id: %d", w.Code)
	}
	if w := r.call(t, "u1", "get_file", `{"id":"`+fakeID("gone")+`"}`); w.Code != http.StatusNotFound {
		t.Fatalf("gone: %d", w.Code)
	}
	if w := r.call(t, "u1", "get_file", `{}`); w.Code != http.StatusBadRequest {
		t.Fatalf("no id: %d", w.Code)
	}
}

// Paging: the page size is a package constant the test cannot shrink, so a
// file of 6,500 bytes is read in one page; the offset arithmetic is checked
// at the end of the text instead.
func TestGetFileOffsets(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	var got struct {
		Text       string `json:"text"`
		Offset     int    `json:"offset"`
		NextOffset *int   `json:"next_offset"`
		TextBytes  int    `json:"text_bytes"`
	}
	w := r.call(t, "u1", "get_file", `{"id":"`+fakeID("notes")+`","offset":6487}`)
	decode(t, w, &got)
	if w.Code != http.StatusOK || got.Text != "line of text\n" || got.Offset != 6487 || got.NextOffset != nil || got.TextBytes != 6500 {
		t.Fatalf("offset: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "get_file", `{"id":"`+fakeID("notes")+`","offset":9999}`); w.Code != http.StatusBadRequest {
		t.Fatalf("past the end: %d %s", w.Code, w.Body)
	}
	if w := r.call(t, "u1", "get_file", `{"id":"`+fakeID("notes")+`","offset":-1}`); w.Code != http.StatusBadRequest {
		t.Fatalf("negative: %d", w.Code)
	}
}

func TestSaveFileOnlyUnderTheConnectorsFolder(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	w := r.call(t, "u1", "save_file", `{"name":"summary","content":"# Summary"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"name":"summary.md"`) || !strings.Contains(w.Body.String(), "nothing was replaced") {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	w = r.call(t, "u1", "save_file", `{"name":"summary.md","content":"again","folder":"runs/today"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"path":"/Privasys/runs/today"`) {
		t.Fatalf("subfolder: %d %s", w.Code, w.Body)
	}
	w = r.call(t, "u1", "save_file", `{"name":"summary.md","content":"third"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"name":"summary (2).md"`) {
		t.Fatalf("suffix: %d %s", w.Code, w.Body)
	}
	d := r.drivers[0]
	if len(d.saved) != 3 || !strings.HasPrefix(d.saved[0], "/summary.md:text/markdown:# Summary") || !strings.HasPrefix(d.saved[1], "runs/today/summary.md:") {
		t.Fatalf("what the driver was asked: %v", d.saved)
	}
	// Anything outside the folder, any name the driver would not take, and
	// an empty or oversized body, are refused here before a driver is asked.
	for _, body := range []string{
		`{"name":"x.md","content":"x","folder":"../Documents"}`,
		`{"name":"x.md","content":"x","folder":"/Documents"}`,
		`{"name":"../x.md","content":"x"}`,
		`{"name":"x.exe","content":"x"}`,
		`{"name":"x.md","content":""}`,
		`{"name":"x.md","content":"` + strings.Repeat("y", cloud.MaxSave+1) + `"}`,
	} {
		w := r.call(t, "u1", "save_file", body)
		if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%.60s: %d %s", body, w.Code, w.Body)
		}
	}
	if len(d.saved) != 3 {
		t.Fatalf("a refused save reached the driver: %v", d.saved)
	}
	// A read-only capability does not cover a write.
	r.connect(t, "ro", "read")
	if w := r.call(t, "ro", "save_file", `{"name":"x.md","content":"x"}`); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "approved read") {
		t.Fatalf("read-only: %d %s", w.Code, w.Body)
	}
}

func TestChangesAndAccount(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	w := r.call(t, "u1", "changes", `{"since":"","wait_seconds":0}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"cursor":"cur-1"`) || !strings.Contains(w.Body.String(), `"kind":"changed"`) {
		t.Fatalf("changes: %d %s", w.Code, w.Body)
	}
	w = r.call(t, "u1", "account", `{}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"user":"u1@example.org"`) || !strings.Contains(w.Body.String(), `"provider":"microsoft"`) {
		t.Fatalf("account: %d %s", w.Code, w.Body)
	}
	for _, secret := range []string{"rt-1", "at-1", "refresh", "access"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("the credential leaked: %s", w.Body)
		}
	}
}

// The shell's refusals, in this connector's words.
func TestRefusals(t *testing.T) {
	r := newRig(t, true)
	// No credential: 403 with the flags, and the kind named.
	w := r.call(t, "nobody", "list_drives", `{}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"credential_needed":true`) || !strings.Contains(w.Body.String(), cloud.Kind) {
		t.Fatalf("no credential: %d %s", w.Code, w.Body)
	}
	// A credential but no capability.
	_ = r.s.credStore().Put(context.Background(), "u2", store.Account{Provider: cloud.ProviderMicrosoft, User: "u2@example.org", AccessToken: "at", Expiry: time.Now().Add(time.Hour)})
	if w := r.call(t, "u2", "list_drives", `{}`); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "request_access") {
		t.Fatalf("no capability: %d %s", w.Code, w.Body)
	}
	// No acting user at all.
	if w := r.do(http.MethodPost, "/tools/list_drives", nil, `{}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("no acting user: %d", w.Code)
	}
	// The provider refusing the bearer is a 502 that says what to do.
	r.connect(t, "u3")
	acct, _ := r.s.credStore().Get(context.Background(), "u3")
	acct.AccessToken = "bad-token"
	_ = r.s.credStore().Put(context.Background(), "u3", acct)
	if w := r.call(t, "u3", "list_drives", `{}`); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "ask_again") {
		t.Fatalf("refused bearer: %d %s", w.Code, w.Body)
	}
	// Every tool in the manifest is routed at both paths.
	r.connect(t, "u4")
	for tool, body := range map[string]string{"list_drives": "{}", "list_folder": "{}", "search": `{"query":"memo"}`, "changes": "{}", "account": "{}",
		"get_file": `{"id":"` + fakeID("gdoc") + `"}`, "save_file": `{"name":"n.md","content":"x"}`} {
		if w := r.do(http.MethodPost, "/api/v1/mcp/tools/"+tool, asUser("u4"), body); w.Code != http.StatusOK {
			t.Errorf("%s at the agent path: %d %s", tool, w.Code, w.Body)
		}
	}
	if w := r.do(http.MethodGet, "/api/v1/mcp/tools", nil, ""); w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"configure"`) || !strings.Contains(w.Body.String(), `"save_file"`) {
		t.Fatalf("catalogue: %d %.200s", w.Code, w.Body)
	}
}

// With the last capability goes the credential, and the driver with it.
func TestRevokeDropsTheDriver(t *testing.T) {
	r := newRig(t, true)
	r.connect(t, "u1")
	if w := r.call(t, "u1", "list_drives", `{}`); w.Code != http.StatusOK {
		t.Fatal(w.Body)
	}
	w := r.do(http.MethodGet, "/v1/capabilities", asHolder("u1"), "")
	var caps struct {
		Capabilities []struct {
			ID string `json:"capability_id"`
		} `json:"capabilities"`
	}
	decode(t, w, &caps)
	if len(caps.Capabilities) != 1 {
		t.Fatalf("one capability: %s", w.Body)
	}
	if w := r.do(http.MethodDelete, "/v1/capabilities/"+caps.Capabilities[0].ID, asHolder("u1"), ""); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if _, err := r.s.credStore().Get(context.Background(), "u1"); !errors.Is(err, store.ErrNoAccount) {
		t.Fatalf("the credential should be gone: %v", err)
	}
	if !r.drivers[0].closed {
		t.Fatal("the driver should have been closed")
	}
}
