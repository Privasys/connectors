// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"net/http"

	manifest "github.com/Privasys/connectors/mail"
)

// The shape an agent's MCP client speaks: `GET /api/v1/mcp/tools` for the
// catalogue and `POST /api/v1/mcp/tools/<tool>` for a call.
//
// Without it this connector is unreachable by an agent, however well the
// capability and credential machinery works. The harness mounts a tool app by
// fetching that catalogue, and a tool app that does not serve it mounts with
// NO capabilities: the agent then reports having no mail tools, which reads
// exactly like a connector nobody configured. The same failure has already
// cost three rounds of "why is there no Drive tool?" on the harness side.
//
// It is an alias, not a second surface. Every call goes through the same
// wrapper as `/tools/<tool>`, so the acting-user check, the configure gate and
// the capability check are not merely equivalent but identical. A second copy
// of those checks is a second place for them to be relaxed.

func (s *Server) mcpRoutes(m *http.ServeMux) {
	// Served WITHOUT an acting user, and it must be: the agent's MCP client
	// pulls the catalogue on a startup timer, before anyone is acting. That
	// is safe here only because nothing in it varies per holder, which is a
	// property to keep rather than a coincidence.
	m.HandleFunc("GET /api/v1/mcp/tools", func(w http.ResponseWriter, r *http.Request) {
		tools, err := manifest.AgentTools()
		if err != nil {
			// 500 rather than an empty list. An empty catalogue is served
			// silently and looks like a working connector with nothing to
			// offer; a 500 is logged by the caller and says what happened.
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tools": tools})
	})
}
