// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const manifest = `{
  "tools": [
    {"name": "configure", "role": "config", "endpoint": "/configure", "description": "operator only",
     "inputSchema": {"type": "object", "properties": {"idp_issuer": {"type": "string"}}}},
    {"name": "list_things", "role": "inference", "endpoint": "/tools/list_things", "description": "list",
     "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}}},
    {"name": "account", "role": "status", "endpoint": "/tools/account", "description": "which account"}
  ]
}`

func TestCatalogueOmitsConfigureAndFillsSchemas(t *testing.T) {
	m, err := Parse([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	tools, err := m.AgentTools()
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 {
		t.Fatalf("want the two agent tools, got %d", len(tools))
	}
	for _, tool := range tools {
		if tool.Name == "configure" {
			t.Fatal("configure is advertised to the agent")
		}
		if len(tool.InputSchema) == 0 {
			t.Fatalf("%s has no input_schema, so the model will invent arguments", tool.Name)
		}
	}
	if eps := m.Endpoints(); len(eps) != 2 || eps[0] != "/tools/list_things" {
		t.Fatalf("endpoints: %v", eps)
	}
}

func TestCatalogueRouteAndEmptyManifest(t *testing.T) {
	m, _ := Parse([]byte(manifest))
	mux := http.NewServeMux()
	m.CatalogueRoute(mux)
	r := httptest.NewRequest(http.MethodGet, CataloguePath, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("catalogue: %d %s", w.Code, w.Body)
	}
	var got struct {
		Tools []struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"input_schema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Tools) != 2 {
		t.Fatalf("catalogue body: %v %s", err, w.Body)
	}

	// An empty catalogue is a 500, never a silent empty list.
	empty, _ := Parse([]byte(`{"tools":[{"name":"configure","role":"config"}]}`))
	mux = http.NewServeMux()
	empty.CatalogueRoute(mux)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("an empty catalogue must fail loudly, got %d", w.Code)
	}
}

func TestAgentPathIsDerivedFromTheToolPath(t *testing.T) {
	if got := AgentPath("/tools/list_things"); got != "/api/v1/mcp/tools/list_things" {
		t.Fatalf("AgentPath = %q", got)
	}
}
