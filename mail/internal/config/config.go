// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package config holds the deployment settings an owner supplies once.
//
// Not baked into the image, because the same image serves dev and production
// and the peer it trusts differs between them. Not read from the environment
// either: the platform's configure-then-freeze path commits a hash of what was
// set into the RA-TLS leaf, so what this service was told is part of what it
// can be checked against. An environment variable is invisible to that.
//
// Everything here names a PEER. Nothing here is a secret: holder credentials
// never pass through this path.
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
	// DriveHost is the resource service this connector keeps credentials in.
	DriveHost string `json:"drive_host"`

	// DriveAppID pins WHO that service is. Without it the attested dial would
	// accept any enclave answering the name, so it is required rather than
	// optional: a connector that cannot name its peer should not start.
	DriveAppID string `json:"drive_app_id"`

	// DriveDigest optionally pins WHAT it runs. Left empty, any build of the
	// pinned app is accepted, which is usually right: an ordinary Drive
	// release should not take every mailbox offline.
	DriveDigest string `json:"drive_digest,omitempty"`
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.DriveHost) == "" {
		return errors.New("drive_host is required: the resource service is named, never guessed")
	}
	if normaliseAppID(c.DriveAppID) == "" {
		return errors.New("drive_app_id must be a 32-character app id: without it the attested dial would trust any enclave that answers the name")
	}
	if d := strings.TrimSpace(c.DriveDigest); d != "" && len(d) != 64 {
		return fmt.Errorf("drive_digest must be a 64-character sha256, got %d characters", len(d))
	}
	return nil
}

// Normalised returns the config as it should be stored and used.
func (c Config) Normalised() Config {
	return Config{
		DriveHost:   strings.ToLower(strings.TrimSpace(c.DriveHost)),
		DriveAppID:  normaliseAppID(c.DriveAppID),
		DriveDigest: strings.ToLower(strings.TrimSpace(c.DriveDigest)),
	}
}

func normaliseAppID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "app:")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return ""
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return ""
		}
	}
	return s
}

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
		// Refuse rather than run on half of it. A connector pointing at an
		// unpinned peer is worse than one that will not start.
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
