// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package caldavdrv

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fakeServer is the smallest CalDAV server the driver can be exercised
// against: principal and home discovery over PROPFIND (with a redirect on
// the well-known path, as real providers answer), calendar listing, a
// time-range calendar-query, sync-collection, and GET, PUT and DELETE with
// the conditional headers. It is deliberately literal, with no library on
// the server side: what the driver sends is checked against what a server
// would read, not against the same code that wrote it.
type fakeServer struct {
	srv *httptest.Server

	mu       sync.Mutex
	user     string
	password string
	bearer   string
	cals     map[string]*fakeCalendar // by collection path
	noSync   bool                     // a server with ctags only
	requests []string                 // method + path, for the assertions
}

type fakeCalendar struct {
	name    string
	objects map[string]*fakeObject // by object path
	version int                    // bumped on every write: the ctag and the sync token
	deleted map[string]int         // path -> version deleted at
}

type fakeObject struct {
	data    string
	etag    string
	version int
	start   time.Time
	end     time.Time
	recurs  bool
}

func newFakeServer() *fakeServer {
	f := &fakeServer{user: "me@example.org", password: "app-pw", cals: map[string]*fakeCalendar{}}
	f.cals["/cal/me/personal/"] = &fakeCalendar{name: "Personal", objects: map[string]*fakeObject{}, deleted: map[string]int{}, version: 1}
	f.cals["/cal/me/work/"] = &fakeCalendar{name: "Work", objects: map[string]*fakeObject{}, deleted: map[string]int{}, version: 1}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

func (f *fakeServer) close() { f.srv.Close() }

// put stores an object as a client would, from raw iCalendar text.
func (f *fakeServer) put(calPath, name, data string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.cals[calPath]
	c.version++
	o := &fakeObject{data: data, version: c.version, etag: fmt.Sprintf("e%d", c.version)}
	o.start, o.end, o.recurs = spanOf(data)
	c.objects[calPath+name] = o
	delete(c.deleted, calPath+name)
	return o.etag
}

var (
	dtStartRe = regexp.MustCompile(`(?m)^DTSTART(?:;[^:]*)?:(\S+)`)
	dtEndRe   = regexp.MustCompile(`(?m)^DTEND(?:;[^:]*)?:(\S+)`)
)

func spanOf(data string) (start, end time.Time, recurs bool) {
	parse := func(v string) time.Time {
		for _, layout := range []string{"20060102T150405Z", "20060102T150405", "20060102"} {
			if t, err := time.Parse(layout, v); err == nil {
				return t
			}
		}
		return time.Time{}
	}
	if m := dtStartRe.FindStringSubmatch(data); m != nil {
		start = parse(m[1])
	}
	if m := dtEndRe.FindStringSubmatch(data); m != nil {
		end = parse(m[1])
	} else {
		end = start.Add(time.Hour)
	}
	recurs = strings.Contains(data, "\nRRULE:")
	return
}

func (f *fakeServer) authorised(r *http.Request) bool {
	if f.bearer != "" {
		return r.Header.Get("Authorization") == "Bearer "+f.bearer
	}
	u, p, ok := r.BasicAuth()
	return ok && u == f.user && p == f.password
}

func (f *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	if !f.authorised(r) {
		w.Header().Set("WWW-Authenticate", `Basic realm="caldav"`)
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	switch r.Method {
	case "PROPFIND":
		f.propfind(w, r, string(body))
	case "REPORT":
		f.report(w, r, string(body))
	case http.MethodGet:
		f.get(w, r)
	case http.MethodPut:
		f.putObject(w, r, string(body))
	case http.MethodDelete:
		f.deleteObject(w, r)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func (f *fakeServer) propfind(w http.ResponseWriter, r *http.Request, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path
	switch {
	case p == "/.well-known/caldav":
		// As real providers answer: the context URL is elsewhere.
		http.Redirect(w, r, "/dav/", http.StatusMovedPermanently)
		return
	case p == "/dav/" || p == "/":
		multi(w, response(p, `<D:current-user-principal><D:href>/principals/me/</D:href></D:current-user-principal>`))
		return
	case p == "/principals/me/":
		multi(w, response(p, `<C:calendar-home-set><D:href>`+f.srv.URL+`/cal/me/</D:href></C:calendar-home-set>`))
		return
	case p == "/cal/me/":
		var parts []string
		parts = append(parts, response(p, `<D:resourcetype><D:collection/></D:resourcetype><D:displayname>Home</D:displayname>`))
		if r.Header.Get("Depth") != "0" {
			for _, path := range f.calendarPaths() {
				parts = append(parts, f.calendarResponse(path))
			}
		}
		multi(w, parts...)
		return
	}
	if c, ok := f.cals[p]; ok {
		props := `<D:resourcetype><D:collection/><C:calendar/></D:resourcetype><D:displayname>` + c.name + `</D:displayname>`
		if strings.Contains(body, "getctag") {
			props += `<CS:getctag>ctag-` + strconv.Itoa(c.version) + `</CS:getctag>`
			if !f.noSync {
				props += `<D:sync-token>http://fake/sync/` + strconv.Itoa(c.version) + `</D:sync-token>`
			}
		}
		multi(w, response(p, props))
		return
	}
	http.NotFound(w, r)
}

func (f *fakeServer) calendarPaths() []string {
	var out []string
	for p := range f.cals {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (f *fakeServer) calendarResponse(path string) string {
	c := f.cals[path]
	return response(path, `<D:resourcetype><D:collection/><C:calendar/></D:resourcetype><D:displayname>`+c.name+
		`</D:displayname><C:supported-calendar-component-set><C:comp name="VEVENT"/></C:supported-calendar-component-set>`)
}

var timeRangeRe = regexp.MustCompile(`time-range start="([0-9TZ]+)" end="([0-9TZ]+)"`)

func (f *fakeServer) report(w http.ResponseWriter, r *http.Request, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.cals[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.Contains(body, "calendar-query"):
		var from, to time.Time
		if m := timeRangeRe.FindStringSubmatch(body); m != nil {
			from, _ = time.Parse("20060102T150405Z", m[1])
			to, _ = time.Parse("20060102T150405Z", m[2])
		}
		var parts []string
		for _, path := range sortedKeys(c.objects) {
			o := c.objects[path]
			if !from.IsZero() && !o.recurs && !(o.start.Before(to) && o.end.After(from)) {
				continue
			}
			parts = append(parts, objectResponse(path, o))
		}
		multi(w, parts...)
	case strings.Contains(body, "sync-collection"):
		if f.noSync {
			http.Error(w, "no sync-collection here", http.StatusForbidden)
			return
		}
		since := 0
		if m := regexp.MustCompile(`sync-token>http://fake/sync/(\d+)<`).FindStringSubmatch(body); m != nil {
			since, _ = strconv.Atoi(m[1])
		}
		var parts []string
		for _, path := range sortedKeys(c.objects) {
			if o := c.objects[path]; o.version > since {
				parts = append(parts, objectResponse(path, o))
			}
		}
		for path, v := range c.deleted {
			if v > since {
				parts = append(parts, `<D:response><D:href>`+path+`</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>`)
			}
		}
		parts = append(parts, `<D:sync-token>http://fake/sync/`+strconv.Itoa(c.version)+`</D:sync-token>`)
		multi(w, parts...)
	default:
		http.Error(w, "unknown report", http.StatusBadRequest)
	}
}

func (f *fakeServer) find(path string) (*fakeCalendar, *fakeObject) {
	for calPath, c := range f.cals {
		if strings.HasPrefix(path, calPath) {
			return c, c.objects[path]
		}
	}
	return nil, nil
}

func (f *fakeServer) get(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, o := f.find(r.URL.Path)
	if o == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("ETag", `"`+o.etag+`"`)
	_, _ = io.WriteString(w, o.data)
}

func (f *fakeServer) putObject(w http.ResponseWriter, r *http.Request, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, o := f.find(r.URL.Path)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("If-None-Match") == "*" && o != nil {
		http.Error(w, "exists", http.StatusPreconditionFailed)
		return
	}
	if im := r.Header.Get("If-Match"); im != "" && (o == nil || im != `"`+o.etag+`"`) {
		http.Error(w, "etag", http.StatusPreconditionFailed)
		return
	}
	c.version++
	n := &fakeObject{data: body, version: c.version, etag: fmt.Sprintf("e%d", c.version)}
	n.start, n.end, n.recurs = spanOf(body)
	c.objects[r.URL.Path] = n
	// Like Google: no ETag on the PUT answer, the client has to ask.
	if o == nil {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (f *fakeServer) deleteObject(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, o := f.find(r.URL.Path)
	if o == nil {
		http.NotFound(w, r)
		return
	}
	if im := r.Header.Get("If-Match"); im != "" && im != `"`+o.etag+`"` {
		http.Error(w, "etag", http.StatusPreconditionFailed)
		return
	}
	c.version++
	delete(c.objects, r.URL.Path)
	c.deleted[r.URL.Path] = c.version
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- XML

func multi(w http.ResponseWriter, parts ...string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	_, _ = io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CS="http://calendarserver.org/ns/">`+
		strings.Join(parts, "")+`</D:multistatus>`)
}

func response(href, props string) string {
	return `<D:response><D:href>` + href + `</D:href><D:propstat><D:prop>` + props + `</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`
}

func objectResponse(path string, o *fakeObject) string {
	var data strings.Builder
	_ = xml.EscapeText(&data, []byte(o.data))
	return response(path, `<D:getetag>"`+o.etag+`"</D:getetag><C:calendar-data>`+data.String()+`</C:calendar-data>`)
}

func sortedKeys(m map[string]*fakeObject) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- fixtures

// vevent builds an iCalendar object from property lines.
func vevent(lines ...string) string {
	return "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//fake//EN\r\nBEGIN:VEVENT\r\n" +
		strings.Join(lines, "\r\n") + "\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
}

func ts(t time.Time) string { return t.UTC().Format("20060102T150405Z") }
