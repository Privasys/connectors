// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package mail carries the connector's manifest into the binary.
//
// It exists only so `privasys.json` has exactly one copy. That file is already
// the catalogue the control plane learns from, as an image label; it is now
// also the catalogue an AGENT is served, so the descriptions a model reads are
// the ones that were reviewed, and a tool cannot be described two ways.
//
// The alternative was a second copy in Go with a CI check comparing them. A
// check that compares two hand-written copies is a check that will one day be
// weakened to make a build pass.
package mail

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed privasys.json
var manifestJSON []byte

// Tool is one entry of the catalogue, in the shape the agent's MCP client
// expects. `input_schema` is snake_case here and camelCase in the manifest,
// because the two are different contracts and neither gets to rename the
// other.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type manifestTool struct {
	Name        string          `json:"name"`
	Role        string          `json:"role"`
	Endpoint    string          `json:"endpoint"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

var (
	once      sync.Once
	agentSet  []Tool
	parseErr  error
	emptyArgs = json.RawMessage(`{"type":"object"}`)
)

// AgentTools is the catalogue served to an agent: every tool except the
// owner-only ones.
//
// `configure` is excluded deliberately rather than by accident of ordering. It
// points this deployment at the service that holds every holder's credential,
// and an agent that could call it could move them. It is the operator's, and
// the operator reaches it through the platform.
func AgentTools() ([]Tool, error) {
	once.Do(func() {
		var doc struct {
			Tools []manifestTool `json:"tools"`
		}
		if err := json.Unmarshal(manifestJSON, &doc); err != nil {
			parseErr = fmt.Errorf("the embedded manifest will not parse: %w", err)
			return
		}
		for _, t := range doc.Tools {
			if t.Role == "config" || t.Name == "" {
				continue
			}
			schema := t.InputSchema
			if len(schema) == 0 {
				// A tool with no schema is a tool the model will call with
				// whatever it invents, so give it the empty object rather
				// than nothing.
				schema = emptyArgs
			}
			agentSet = append(agentSet, Tool{
				Name: t.Name, Description: t.Description, InputSchema: schema,
			})
		}
		if len(agentSet) == 0 {
			// Mounting an empty tool set reads to a user as "the agent has no
			// mail tools", which is indistinguishable from nobody having
			// configured one. Fail loudly instead.
			parseErr = fmt.Errorf("the embedded manifest describes no agent tools")
		}
	})
	return agentSet, parseErr
}
