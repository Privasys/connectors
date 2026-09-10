// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func catalogue(t *testing.T, s *Server) []map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("catalogue: %d %s", w.Code, w.Body)
	}
	var got struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got.Tools
}

// The catalogue is how a tool acquires its capabilities. A connector that does
// not serve it mounts with NO tools, and the agent then reports having no mail
// tools at all, which reads exactly like a connector nobody configured.
func TestCatalogueIsServedWithoutAnActingUser(t *testing.T) {
	s, _ := guardedServer(t)
	tools := catalogue(t, s)
	if len(tools) == 0 {
		t.Fatal("an empty catalogue mounts a tool with no capabilities")
	}
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			t.Fatalf("a tool with no name: %v", tool)
		}
		if d, _ := tool["description"].(string); d == "" {
			t.Errorf("%s has no description, so the model cannot tell when to use it", name)
		}
		if tool["input_schema"] == nil {
			t.Errorf("%s has no input_schema, so the model will invent arguments", name)
		}
	}
}

// configure points this deployment at the service holding every holder's
// credential. An agent that could call it could move them, so it must not
// appear in the catalogue and must not be callable at the agent's path.
func TestConfigureIsNotAnAgentTool(t *testing.T) {
	s, _ := guardedServer(t)
	for _, tool := range catalogue(t, s) {
		if name, _ := tool["name"].(string); name == "configure" {
			t.Fatal("configure is advertised to the agent")
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/tools/configure",
		strings.NewReader(`{"drive_host":"attacker.example","drive_app_id":"00000000000000000000000000000000"}`))
	r.Header.Set(SubjectHeader, "user-1")
	r.Header.Set(PeerAppHeader, testApp)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	// 405 rather than 404, because the linking page's `GET /` matches the path
	// for a different method. Either is a refusal; what must never happen is a
	// 2xx, which would mean an agent had just repointed the service that holds
	// every holder's credential.
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("configure must not be reachable at the agent's path, got %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "attacker.example") {
		t.Fatalf("the configure handler ran: %s", w.Body)
	}
}

// Every advertised tool must be callable at the agent's path, or the agent
// gets a 404 from something the catalogue promised. The reverse also matters:
// a tool reachable there but unadvertised is one nobody reviewed.
func TestEveryAdvertisedToolIsCallableAndEnforced(t *testing.T) {
	s, _ := guardedServer(t)
	mint(t, s, "user-1", []string{"read", "write"})

	for _, tool := range catalogue(t, s) {
		name, _ := tool["name"].(string)
		path := "/api/v1/mcp/tools/" + name

		// Reachable, and covered by the capability.
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		r.Header.Set(SubjectHeader, "user-1")
		r.Header.Set(PeerAppHeader, testApp)
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		if w.Code == http.StatusNotFound {
			t.Errorf("%s is advertised but not routed", name)
			continue
		}

		// And the checks are the SAME ones, not merely similar: no acting
		// user is refused here exactly as it is on /tools/.
		r = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		w = httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s served a call with no acting user: %d", name, w.Code)
		}

		// And an app with no capability is refused here too.
		r = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		r.Header.Set(SubjectHeader, "user-1")
		r.Header.Set(PeerAppHeader, "0123456789abcdef0123456789abcdef")
		w = httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s served an app with no capability: %d %s", name, w.Code, w.Body)
		}
	}
}

// The two paths are one closure, so a read-only capability must stop a write
// tool at the agent's path exactly as it does at the connector's own.
func TestWritePermissionIsCheckedOnTheAgentPathToo(t *testing.T) {
	s, _ := guardedServer(t)
	mint(t, s, "user-1", []string{"read"})

	for _, c := range []struct {
		path string
		want int
	}{
		{"/api/v1/mcp/tools/list_messages", http.StatusOK},
		{"/api/v1/mcp/tools/set_labels", http.StatusForbidden},
		{"/api/v1/mcp/tools/create_draft", http.StatusForbidden},
	} {
		r := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(`{}`))
		r.Header.Set(SubjectHeader, "user-1")
		r.Header.Set(PeerAppHeader, testApp)
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: want %d, got %d %s", c.path, c.want, w.Code, w.Body)
		}
	}
}
