// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package config is the shape of this deployment's settings. Storing them,
// gating on them and attesting them is the sdk's (package configure); what
// they are is this connector's, and here it is the root of holder identity
// and nothing else.
//
// Nothing here is a secret, and nothing here names a storage peer: this
// service keeps no holder data at rest, so there is no peer to name.
package config

import (
	"strings"

	"github.com/Privasys/connectors/sdk/configure"
)

// The platform's own identity provider, and the audience the wallet mints its
// platform token for.
const (
	DefaultIdpIssuer   = configure.DefaultIdpIssuer
	DefaultIdpAudience = configure.DefaultIdpAudience
)

type Config struct {
	// IdpIssuer is whose tokens this service will accept as proof of WHICH
	// PERSON is calling, when the wallet dials it directly to mint a
	// capability. It belongs in the configuration rather than in the code
	// because it is the root of holder identity here: an operator who could
	// not see which issuer is trusted could not tell whose approval this
	// connector would honour. Empty means the platform's own.
	IdpIssuer string `json:"idp_issuer,omitempty"`

	// IdpAudience is the audience those tokens must carry, so a token minted
	// for some other service cannot be replayed at this one.
	IdpAudience string `json:"idp_audience,omitempty"`
}

func (c Config) Validate() error { return configure.ValidateIssuer(c.IdpIssuer) }

// Normalised returns the config as it should be stored and used, defaults
// applied here so that what is stored, what is served and what is hashed into
// the certificate are the same two strings.
func (c Config) Normalised() Config {
	out := Config{
		IdpIssuer:   strings.TrimRight(strings.TrimSpace(c.IdpIssuer), "/"),
		IdpAudience: strings.TrimSpace(c.IdpAudience),
	}
	if out.IdpIssuer == "" {
		out.IdpIssuer = DefaultIdpIssuer
	}
	if out.IdpAudience == "" {
		out.IdpAudience = DefaultIdpAudience
	}
	return out
}

// Identity is the root of holder identity.
func (c Config) Identity() (issuer, audience string) { return c.IdpIssuer, c.IdpAudience }

// DigestFields is what the certificate digest covers: the identity provider
// is the whole configuration, and the claim worth attesting, because which
// issuer is trusted decides whose approval can hand a mailbox over.
func (c Config) DigestFields() []string { return []string{c.IdpIssuer, c.IdpAudience} }

// Public is what /configure answers with: whose approvals this deployment
// will honour. Worth showing, because an operator who cannot see the issuer
// cannot tell whose wallet can grant access to a mailbox here.
func (c Config) Public() map[string]any {
	return map[string]any{"idp_issuer": c.IdpIssuer, "idp_audience": c.IdpAudience}
}
