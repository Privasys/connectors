// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package config holds the deployment settings an owner supplies once.
//
// Not baked into the image, because the same image serves dev and production
// and the identity provider it trusts differs between them. Not read from the
// environment either: the platform's configure-then-freeze path commits a hash
// of what was set into the RA-TLS leaf, so what this service was told is part
// of what it can be checked against. An environment variable is invisible to
// that.
//
// Nothing here is a secret, and nothing here names a storage peer: this
// service keeps no holder data at rest, so there is no peer to name. What is
// left is the root of holder identity.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func (c Config) Validate() error {
	// An issuer reached over anything but https would let whoever answers that
	// name decide who the holder is.
	if iss := strings.TrimSpace(c.IdpIssuer); iss != "" && !strings.HasPrefix(iss, "https://") {
		return errors.New("idp_issuer must be an https URL: holder identity is rooted in it")
	}
	return nil
}

// Normalised returns the config as it should be stored and used.
//
// The identity-provider fields are DEFAULTED here rather than at the point of
// use, so that what is stored, what is served from GET /configure and what is
// hashed into the certificate are the same two strings. A default applied
// later would mean the certificate attested an empty field while the service
// trusted a real issuer.
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

// The platform's own identity provider, and the audience the wallet mints its
// platform token for.
const (
	DefaultIdpIssuer   = "https://privasys.id"
	DefaultIdpAudience = "privasys-platform"
)

// Load reads the stored config. A missing file is not an error: it is the
// ordinary state of an app that has been deployed and not yet configured, and
// the platform holds every other endpoint at 503 until it has been.
func Load(path string) (Config, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, false, nil
	}
	if err != nil {
		return Config{}, false, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, false, fmt.Errorf("stored configuration is unreadable: %w", err)
	}
	if err := c.Validate(); err != nil {
		// Refuse rather than run on half of it. A connector trusting an issuer
		// nobody can verify is worse than one that will not start.
		return Config{}, false, fmt.Errorf("stored configuration is invalid: %w", err)
	}
	return c.Normalised(), true, nil
}

func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c.Normalised(), "", "  ")
	if err != nil {
		return err
	}
	// Write and rename, so a crash mid-write cannot leave a truncated file
	// that the next boot refuses to parse.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
