// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package config is the shape of this deployment's settings. Storing them,
// gating on them and attesting them is the sdk's (package configure); what
// they are is this connector's: the root of holder identity, and the OAuth
// client this deployment speaks to Google as.
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
	// capability. Empty means the platform's own.
	IdpIssuer string `json:"idp_issuer,omitempty"`
	// IdpAudience is the audience those tokens must carry.
	IdpAudience string `json:"idp_audience,omitempty"`

	// OAuthClientID and OAuthClientSecret are the Google Cloud OAuth client
	// the deployer created, with https://<host>/v1/oauth/callback as its
	// redirect URI. The secret is sealed exactly as any configured value: it
	// is used at Google's token endpoint and never leaves this process. Both
	// empty means Google accounts cannot be connected here; app passwords
	// still can.
	OAuthClientID     string `json:"oauth_client_id,omitempty"`
	OAuthClientSecret string `json:"oauth_client_secret,omitempty"`
}

func (c Config) Validate() error { return configure.ValidateIssuer(c.IdpIssuer) }

// Normalised returns the config as it should be stored and used, defaults
// applied here so that what is stored, what is served and what is hashed into
// the certificate are the same strings.
func (c Config) Normalised() Config {
	out := Config{
		IdpIssuer:         strings.TrimRight(strings.TrimSpace(c.IdpIssuer), "/"),
		IdpAudience:       strings.TrimSpace(c.IdpAudience),
		OAuthClientID:     strings.TrimSpace(c.OAuthClientID),
		OAuthClientSecret: strings.TrimSpace(c.OAuthClientSecret),
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

// DigestFields is what the certificate digest covers. The client secret
// takes part as the hex of its sha256 rather than as its value, so the
// certificate says WHICH Google client this deployment speaks as (a rotated
// secret changes the digest) without the digest being a function anyone
// could invert from the other, public fields: Google's client secrets are
// long and random, so hashing them first gives nothing away.
func (c Config) DigestFields() []string {
	return []string{c.IdpIssuer, c.IdpAudience, c.OAuthClientID, configure.HashSecret(c.OAuthClientSecret)}
}

// Public is what /configure answers with. The secret is shown as set or not.
func (c Config) Public() map[string]any {
	return map[string]any{
		"idp_issuer":              c.IdpIssuer,
		"idp_audience":            c.IdpAudience,
		"oauth_client_id":         c.OAuthClientID,
		"oauth_client_secret_set": c.OAuthClientSecret != "",
	}
}

// GoogleConfigured reports whether Google accounts can be connected here.
func (c Config) GoogleConfigured() bool { return c.OAuthClientID != "" && c.OAuthClientSecret != "" }
