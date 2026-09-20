// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package config

import (
	"strings"
	"testing"
)

func TestNormalisedDefaultsAndDigest(t *testing.T) {
	c := Config{
		IdpIssuer: " https://idp.example/ ", DriveHost: " Drive.Example ", DriveAppID: "CF7A0D58-5468-4168-84C3-41EBE0CE4025",
		ZoomClientID: " zid ", ZoomClientSecret: " zsecret ", ZoomScopes: "  user:read   recording:read ",
		MicrosoftClientID: "mid", MicrosoftClientSecret: "msecret",
	}.Normalised()
	if c.IdpIssuer != "https://idp.example" || c.IdpAudience != DefaultIdpAudience || c.DriveHost != "drive.example" ||
		c.DriveAppID != "cf7a0d585468416884c341ebe0ce4025" || c.ZoomScopes != "user:read recording:read" {
		t.Errorf("normalised: %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.ZoomConfigured() || !c.MicrosoftConfigured() || !c.DriveConfigured() {
		t.Errorf("configured: %+v", c)
	}
	// The default scopes apply when none are given.
	if d := (Config{}).Normalised(); d.ZoomScopes != DefaultZoomScopes || d.IdpIssuer != DefaultIdpIssuer || d.DriveConfigured() {
		t.Errorf("defaults: %+v", d)
	}
	// Secrets are in the digest as hashes and absent from the public view.
	fields := strings.Join(c.DigestFields(), "\x00")
	if strings.Contains(fields, "zsecret") || strings.Contains(fields, "msecret") || !strings.Contains(fields, "cf7a0d585468416884c341ebe0ce4025") {
		t.Errorf("digest fields: %q", fields)
	}
	rotated := c
	rotated.ZoomClientSecret = "other"
	if strings.Join(rotated.DigestFields(), "\x00") == fields {
		t.Error("a rotated secret must change the digest")
	}
	pub := c.Public()
	if pub["zoom_client_secret_set"] != true || pub["microsoft_client_secret_set"] != true {
		t.Errorf("public: %v", pub)
	}
	for k, v := range pub {
		if s, ok := v.(string); ok && (strings.Contains(s, "secret") && k != "zoom_scopes") {
			t.Errorf("public %s carries a secret: %q", k, s)
		}
	}
}

func TestValidate(t *testing.T) {
	bad := []Config{
		{IdpIssuer: "http://idp.example"},
		{DriveHost: "drive.example"},
		{DriveHost: "drive.example", DriveAppID: "short"},
		{DriveAppID: "cf7a0d585468416884c341ebe0ce4025"},
		{DriveHost: "https://drive.example", DriveAppID: "cf7a0d585468416884c341ebe0ce4025"},
		{DriveHost: "drive.example", DriveAppID: "cf7a0d585468416884c341ebe0ce4025", DriveDigest: "abc"},
	}
	for _, c := range bad {
		if err := c.Normalised().Validate(); err == nil {
			t.Errorf("accepted: %+v", c)
		}
	}
	good := Config{DriveHost: "drive.example", DriveAppID: "cf7a0d585468416884c341ebe0ce4025", DriveDigest: strings.Repeat("ab", 32)}
	if err := good.Normalised().Validate(); err != nil {
		t.Errorf("refused: %v", err)
	}
	if err := (Config{}).Normalised().Validate(); err != nil {
		t.Errorf("an empty configuration is a deployment that archives nothing: %v", err)
	}
}
