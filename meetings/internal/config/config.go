// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package config is the shape of this deployment's settings. Storing them,
// gating on them and attesting them is the sdk's (package configure); what
// they are is this connector's: the root of holder identity, the Drive this
// deployment archives into and who that Drive must be, and the OAuth clients
// this deployment speaks to Zoom and to Microsoft as.
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Privasys/connectors/sdk/configure"
	"github.com/Privasys/connectors/sdk/drive"
)

// The platform's own identity provider, and the audience the wallet mints its
// platform token for.
const (
	DefaultIdpIssuer   = configure.DefaultIdpIssuer
	DefaultIdpAudience = configure.DefaultIdpAudience
)

// DefaultZoomScopes are the granular scopes of a current Zoom app: who the
// account is, the holder's own recordings, and the files of one recording.
// A Zoom app configured with the classic scopes uses `user:read
// recording:read meeting:read` instead, which is why the scopes are a
// setting rather than a constant.
const DefaultZoomScopes = "user:read:user cloud_recording:read:list_user_recordings cloud_recording:read:list_recording_files"

type Config struct {
	// IdpIssuer is whose tokens this service will accept as proof of WHICH
	// PERSON is calling, when the wallet dials it directly to mint a
	// capability. Empty means the platform's own.
	IdpIssuer string `json:"idp_issuer,omitempty"`
	// IdpAudience is the audience those tokens must carry.
	IdpAudience string `json:"idp_audience,omitempty"`

	// DriveHost is the resource service this connector archives transcripts
	// in. DriveAppID pins WHO that service is: without it the attested dial
	// would accept any enclave answering the name. DriveDigest optionally
	// pins WHAT it runs; left empty, any build of the pinned app is
	// accepted, which is usually right: an ordinary Drive release should
	// not stop every archive. All three may be empty on a deployment that
	// archives nothing; then save_transcript says so.
	DriveHost   string `json:"drive_host,omitempty"`
	DriveAppID  string `json:"drive_app_id,omitempty"`
	DriveDigest string `json:"drive_digest,omitempty"`

	// The Zoom Marketplace OAuth app this deployment signs Zoom accounts in
	// with, and the scopes it asks for. The secret is sealed exactly as any
	// configured value and never leaves this process.
	ZoomClientID     string `json:"zoom_client_id,omitempty"`
	ZoomClientSecret string `json:"zoom_client_secret,omitempty"`
	ZoomScopes       string `json:"zoom_scopes,omitempty"`

	// The Entra app registration this deployment signs Microsoft accounts
	// in with.
	MicrosoftClientID     string `json:"microsoft_client_id,omitempty"`
	MicrosoftClientSecret string `json:"microsoft_client_secret,omitempty"`
}

func (c Config) Validate() error {
	if err := configure.ValidateIssuer(c.IdpIssuer); err != nil {
		return err
	}
	host, app := strings.TrimSpace(c.DriveHost), strings.TrimSpace(c.DriveAppID)
	if host != "" && drive.NormaliseAppID(app) == "" {
		return errors.New("drive_app_id must be a 32-character app id: without it the attested dial would trust any enclave that answers the name")
	}
	if host == "" && app != "" {
		return errors.New("drive_app_id names a peer but drive_host does not say where it is")
	}
	if d := strings.TrimSpace(c.DriveDigest); d != "" && len(d) != 64 {
		return fmt.Errorf("drive_digest must be a 64-character sha256, got %d characters", len(d))
	}
	if strings.Contains(c.DriveHost, "/") || strings.Contains(c.DriveHost, ":") {
		return errors.New("drive_host is a hostname, not a URL")
	}
	return nil
}

// Normalised returns the config as it should be stored and used, defaults
// applied here so that what is stored, what is served and what is hashed into
// the certificate are the same strings.
func (c Config) Normalised() Config {
	out := Config{
		IdpIssuer:             strings.TrimRight(strings.TrimSpace(c.IdpIssuer), "/"),
		IdpAudience:           strings.TrimSpace(c.IdpAudience),
		DriveHost:             strings.ToLower(strings.TrimSpace(c.DriveHost)),
		DriveAppID:            drive.NormaliseAppID(c.DriveAppID),
		DriveDigest:           strings.ToLower(strings.TrimSpace(c.DriveDigest)),
		ZoomClientID:          strings.TrimSpace(c.ZoomClientID),
		ZoomClientSecret:      strings.TrimSpace(c.ZoomClientSecret),
		ZoomScopes:            strings.Join(strings.Fields(c.ZoomScopes), " "),
		MicrosoftClientID:     strings.TrimSpace(c.MicrosoftClientID),
		MicrosoftClientSecret: strings.TrimSpace(c.MicrosoftClientSecret),
	}
	if out.IdpIssuer == "" {
		out.IdpIssuer = DefaultIdpIssuer
	}
	if out.IdpAudience == "" {
		out.IdpAudience = DefaultIdpAudience
	}
	if out.ZoomScopes == "" {
		out.ZoomScopes = DefaultZoomScopes
	}
	return out
}

// Identity is the root of holder identity.
func (c Config) Identity() (issuer, audience string) { return c.IdpIssuer, c.IdpAudience }

// DigestFields is what the certificate digest covers: the identity root,
// the Drive peer's identity, and the OAuth clients. Each secret takes part
// as the hex of its sha256 rather than as its value, so the certificate says
// WHICH client this deployment speaks as (a rotated secret changes the
// digest) without the digest being a function anyone could invert from the
// other, public fields.
func (c Config) DigestFields() []string {
	return []string{
		c.IdpIssuer, c.IdpAudience,
		c.DriveHost, c.DriveAppID, c.DriveDigest,
		c.ZoomClientID, configure.HashSecret(c.ZoomClientSecret), c.ZoomScopes,
		c.MicrosoftClientID, configure.HashSecret(c.MicrosoftClientSecret),
	}
}

// Public is what /configure answers with. Each secret is shown as set or
// not.
func (c Config) Public() map[string]any {
	return map[string]any{
		"idp_issuer":                  c.IdpIssuer,
		"idp_audience":                c.IdpAudience,
		"drive_host":                  c.DriveHost,
		"drive_app_id":                c.DriveAppID,
		"drive_digest":                c.DriveDigest,
		"zoom_client_id":              c.ZoomClientID,
		"zoom_client_secret_set":      c.ZoomClientSecret != "",
		"zoom_scopes":                 c.ZoomScopes,
		"microsoft_client_id":         c.MicrosoftClientID,
		"microsoft_client_secret_set": c.MicrosoftClientSecret != "",
	}
}

// ZoomConfigured and MicrosoftConfigured report which providers accounts can
// be connected at here.
func (c Config) ZoomConfigured() bool { return c.ZoomClientID != "" && c.ZoomClientSecret != "" }
func (c Config) MicrosoftConfigured() bool {
	return c.MicrosoftClientID != "" && c.MicrosoftClientSecret != ""
}

// DriveConfigured reports whether this deployment can archive at all.
func (c Config) DriveConfigured() bool { return c.DriveHost != "" && c.DriveAppID != "" }
