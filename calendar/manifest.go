// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package calendar carries the connector's manifest into the binary.
//
// It exists only so `privasys.json` has exactly one copy. That file is already
// the catalogue the control plane learns from, as an image label; it is also
// the catalogue an AGENT is served, so the descriptions a model reads are the
// ones that were reviewed, and a tool cannot be described two ways.
package calendar

import (
	_ "embed"

	"github.com/Privasys/connectors/sdk/mcp"
)

//go:embed privasys.json
var manifestJSON []byte

// Manifest is the parsed catalogue. A manifest that will not parse is a build
// that must not ship, so this panics rather than serving nothing.
func Manifest() *mcp.Manifest {
	m, err := mcp.Parse(manifestJSON)
	if err != nil {
		panic(err)
	}
	return m
}
