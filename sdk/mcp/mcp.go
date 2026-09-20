// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package mcp is the surface an agent's MCP client speaks: the catalogue at
// `GET /api/v1/mcp/tools` and a call at `POST /api/v1/mcp/tools/<tool>`.
//
// The catalogue is served from the connector's embedded `privasys.json`,
// which is also the label the control plane reads, so the descriptions a
// model sees are the ones that were reviewed and a tool cannot be described
// two ways. The alternative was a second copy in Go with a CI check comparing
// them, and a check that compares two hand-written copies is a check that
// will one day be weakened to make a build pass.
//
// Without this surface a connector is unreachable by an agent, however well
// the capability and credential machinery works. The harness mounts a tool
// app by fetching the catalogue, and a tool app that does not serve it mounts
// with NO capabilities: the agent then reports having no tools, which reads
// exactly like a connector nobody configured.
package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Privasys/connectors/sdk/web"
)

// ToolPrefix is where an agent's MCP client calls a tool.
const ToolPrefix = "/api/v1/mcp/tools/"

// CataloguePath is where it reads the catalogue.
const CataloguePath = "/api/v1/mcp/tools"

// Tool is one entry of the catalogue, in the shape the agent's MCP client
// expects. `input_schema` is snake_case here and camelCase in the manifest,
// because the two are different contracts and neither gets to rename the
// other.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// Manifest is the parsed `privasys.json`: what the control plane reads, and
// the one source of the agent's catalogue.
type Manifest struct {
	tools []manifestTool
}

type manifestTool struct {
	Name        string          `json:"name"`
	Role        string          `json:"role"`
	Endpoint    string          `json:"endpoint"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

var emptyArgs = json.RawMessage(`{"type":"object"}`)

// Parse reads an embedded manifest.
func Parse(manifestJSON []byte) (*Manifest, error) {
	var doc struct {
		Tools []manifestTool `json:"tools"`
	}
	if err := json.Unmarshal(manifestJSON, &doc); err != nil {
		return nil, fmt.Errorf("the embedded manifest will not parse: %w", err)
	}
	return &Manifest{tools: doc.Tools}, nil
}

// AgentTools is the catalogue served to an agent: every tool except the
// owner-only ones.
//
// `configure` is excluded deliberately rather than by accident of ordering
// (its role is "config"). It names the identity provider whose word this
// deployment takes on who a holder is, and an agent that could call it could
// decide whose approvals count. It is the operator's, and the operator
// reaches it through the platform.
func (m *Manifest) AgentTools() ([]Tool, error) {
	var out []Tool
	for _, t := range m.tools {
		if t.Role == "config" || t.Name == "" {
			continue
		}
		schema := t.InputSchema
		if len(schema) == 0 {
			// A tool with no schema is a tool the model will call with
			// whatever it invents, so give it the empty object rather than
			// nothing.
			schema = emptyArgs
		}
		out = append(out, Tool{Name: t.Name, Description: t.Description, InputSchema: schema})
	}
	if len(out) == 0 {
		// Mounting an empty tool set reads to a user as "the agent has no
		// tools", which is indistinguishable from nobody having configured
		// one. Fail loudly instead.
		return nil, fmt.Errorf("the embedded manifest describes no agent tools")
	}
	return out, nil
}

// Endpoints returns the endpoint of every agent tool in the manifest, so a
// test can check each one is routed.
func (m *Manifest) Endpoints() []string {
	var out []string
	for _, t := range m.tools {
		if t.Role == "config" || t.Name == "" {
			continue
		}
		out = append(out, t.Endpoint)
	}
	return out
}

// CatalogueRoute serves the catalogue.
//
// Served WITHOUT an acting user, and it must be: the agent's MCP client pulls
// the catalogue on a startup timer, before anyone is acting. That is safe only
// because nothing in it varies per holder, which is a property to keep rather
// than a coincidence.
func (m *Manifest) CatalogueRoute(mux *http.ServeMux) {
	mux.HandleFunc("GET "+CataloguePath, func(w http.ResponseWriter, r *http.Request) {
		tools, err := m.AgentTools()
		if err != nil {
			// 500 rather than an empty list. An empty catalogue is served
			// silently and looks like a working connector with nothing to
			// offer; a 500 is logged by the caller and says what happened.
			web.WriteErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		web.WriteJSON(w, http.StatusOK, map[string]any{"tools": tools})
	})
}

// AgentPath is where an agent's MCP client calls the tool mounted at a
// connector path such as "/tools/list_messages". Derived from the connector's
// path rather than passed separately, so a tool cannot end up mounted under
// one name and callable under another.
func AgentPath(toolPath string) string {
	return ToolPrefix + strings.TrimPrefix(toolPath, "/tools/")
}
