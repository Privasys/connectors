// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package config is the shape of this deployment's settings. Storing them,
// gating on them and attesting them is the sdk's (package configure); what
// they are is this connector's: the root of holder identity, and the two
// OAuth clients this deployment signs Google and Microsoft mailboxes in
// with.
//
// Nothing here names a storage peer: this service keeps no holder data at
// rest, so there is no peer to name. The client secrets are sealed exactly
// as any configured value and are spent at the providers' token endpoints
// and nowhere else.
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

	// The Google Cloud OAuth client this deployment signs Google mailboxes
	// in with, and the Entra app registration for Microsoft mailboxes. Each
	// was created with https://<host>/v1/oauth/callback as its redirect
	// URI. A provider whose pair is empty cannot be connected here, and no
	// password is offered for it instead: Microsoft has none and Google's
	// are on the way out. Providers we reach directly still connect with an
	// app password whatever is set here.
	GoogleClientID        string `json:"google_client_id,omitempty"`
	GoogleClientSecret    string `json:"google_client_secret,omitempty"`
	MicrosoftClientID     string `json:"microsoft_client_id,omitempty"`
	MicrosoftClientSecret string `json:"microsoft_client_secret,omitempty"`
}

func (c Config) Validate() error { return configure.ValidateIssuer(c.IdpIssuer) }

// Normalised returns the config as it should be stored and used, defaults
// applied here so that what is stored, what is served and what is hashed into
// the certificate are the same strings.
func (c Config) Normalised() Config {
	out := Config{
		IdpIssuer:             strings.TrimRight(strings.TrimSpace(c.IdpIssuer), "/"),
		IdpAudience:           strings.TrimSpace(c.IdpAudience),
		GoogleClientID:        strings.TrimSpace(c.GoogleClientID),
		GoogleClientSecret:    strings.TrimSpace(c.GoogleClientSecret),
		MicrosoftClientID:     strings.TrimSpace(c.MicrosoftClientID),
		MicrosoftClientSecret: strings.TrimSpace(c.MicrosoftClientSecret),
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

// DigestFields is what the certificate digest covers: the identity provider,
// which decides whose approval can hand a mailbox over, and the two OAuth
// clients, which decide whose sign-in this deployment can take. Each client
// secret takes part as the hex of its sha256 rather than as its value, so
// the certificate says WHICH clients this deployment speaks as (a rotated
// secret changes the digest) without the digest being a function anyone
// could invert from the other, public fields. The providers' client secrets
// are long and random, so hashing them first gives nothing away.
func (c Config) DigestFields() []string {
	return []string{
		c.IdpIssuer, c.IdpAudience,
		c.GoogleClientID, configure.HashSecret(c.GoogleClientSecret),
		c.MicrosoftClientID, configure.HashSecret(c.MicrosoftClientSecret),
	}
}

// Public is what /configure answers with: whose approvals this deployment
// will honour, and which sign-ins it offers. A secret is shown as set or
// not, never as its value.
func (c Config) Public() map[string]any {
	return map[string]any{
		"idp_issuer":                  c.IdpIssuer,
		"idp_audience":                c.IdpAudience,
		"google_client_id":            c.GoogleClientID,
		"google_client_secret_set":    c.GoogleClientSecret != "",
		"microsoft_client_id":         c.MicrosoftClientID,
		"microsoft_client_secret_set": c.MicrosoftClientSecret != "",
	}
}

// GoogleConfigured and MicrosoftConfigured report which sign-ins this
// deployment offers.
func (c Config) GoogleConfigured() bool { return c.GoogleClientID != "" && c.GoogleClientSecret != "" }

func (c Config) MicrosoftConfigured() bool {
	return c.MicrosoftClientID != "" && c.MicrosoftClientSecret != ""
}
