// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

// Package configure is the platform's configure-then-freeze path, and the
// certificate claim that goes with it.
//
// A connector's settings are not baked into the image, because the same image
// serves dev and production and the identity provider it trusts differs
// between them. They are not read from the environment either: the platform's
// configure-then-freeze path commits a hash of what was set into the RA-TLS
// leaf, so what the service was told is part of what it can be checked
// against. An environment variable is invisible to that.
//
// The runtime holds every other endpoint at 503 until POST /configure
// succeeds, and re-arms the gate on each restart, so a deployment cannot
// serve on settings nobody supplied. What the settings ARE is the
// connector's: the shape lives with the connector as a type satisfying
// Config, and everything about storing it, gating on it and attesting it
// lives here.
package configure

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Privasys/connectors/sdk/web"
)

// The platform's own identity provider, and the audience the wallet mints its
// platform token for. A connector's Config defaults to them.
const (
	DefaultIdpIssuer   = "https://privasys.id"
	DefaultIdpAudience = "privasys-platform"
)

// Config is what a connector's settings type provides. C is the type itself.
type Config[C any] interface {
	// Validate refuses settings the service must not run on.
	Validate() error
	// Normalised returns the settings as they are stored, served and
	// digested: defaults applied, whitespace gone. Applying a default later
	// would mean the certificate attested an empty field while the service
	// trusted a real issuer.
	Normalised() C
	// Identity is the root of holder identity: whose tokens prove WHICH
	// PERSON is calling when the wallet dials the connector directly, and the
	// audience they must carry. Changing it forgets every holder in memory.
	Identity() (issuer, audience string)
	// DigestFields are the values folded into the configuration digest that
	// the certificate carries, in a fixed order. A secret contributes a hash
	// of itself, never the value.
	DigestFields() []string
	// Public is what GET and POST /configure answer with. Never a secret.
	Public() map[string]any
}

// ValidateIssuer is the check every connector's Validate applies to its
// issuer: an issuer reached over anything but https would let whoever answers
// that name decide who the holder is.
func ValidateIssuer(issuer string) error {
	if iss := strings.TrimSpace(issuer); iss != "" && !strings.HasPrefix(iss, "https://") {
		return errors.New("idp_issuer must be an https URL: holder identity is rooted in it")
	}
	return nil
}

// Load reads the stored settings. A missing file is not an error: it is the
// ordinary state of an app that has been deployed and not yet configured, and
// the platform holds every other endpoint at 503 until it has been.
func Load[C Config[C]](path string) (C, bool, error) {
	var zero C
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	var c C
	if err := json.Unmarshal(raw, &c); err != nil {
		return zero, false, fmt.Errorf("stored configuration is unreadable: %w", err)
	}
	if err := c.Validate(); err != nil {
		// Refuse rather than run on half of it. A connector trusting an issuer
		// nobody can verify is worse than one that will not start.
		return zero, false, fmt.Errorf("stored configuration is invalid: %w", err)
	}
	return c.Normalised(), true, nil
}

// Save writes the settings, normalised, with write-and-rename so a crash
// mid-write cannot leave a truncated file the next boot refuses to parse.
func Save[C Config[C]](path string, c C) error {
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ErrNotConfigured is what every holder-facing path returns before configure.
var ErrNotConfigured = errors.New("this deployment has not been configured yet, so it does not know whose approvals to honour")

// Gate is the configure-then-freeze state for one deployment.
type Gate[C Config[C]] struct {
	mu      sync.RWMutex
	path    string
	current C
	set     bool

	// OnApply, when set, is told the new settings after every successful
	// configure, after the shell has swapped its identity root. A connector
	// that needs a value from the settings (an OAuth client, say) takes it
	// here.
	OnApply func(C)
}

// NewGate arms the gate over the settings loaded at startup.
func NewGate[C Config[C]](path string, initial C, alreadySet bool) *Gate[C] {
	return &Gate[C]{path: path, current: initial, set: alreadySet}
}

// Configured reports whether POST /configure has succeeded, now or before a
// restart.
func (g *Gate[C]) Configured() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.set
}

// Current returns the settings in force and whether any are.
func (g *Gate[C]) Current() (C, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.current, g.set
}

// Digest is sha256 over the NUL-separated digest fields of the settings in
// force: the certificate says WHICH configuration is in force, and an
// operator who knows the settings can prove it matches. NUL-separated so no
// combination of values can be rearranged into the same digest as another.
func (g *Gate[C]) Digest() ([]byte, bool) {
	cur, set := g.Current()
	if !set {
		return nil, false
	}
	sum := sha256.Sum256([]byte(strings.Join(cur.DigestFields(), "\x00")))
	return sum[:], true
}

// Routes registers POST and GET /configure. apply is called after every
// successful save, under no lock of this package, with the new identity root
// and whether it changed; the shell swaps its verifier and forgets everyone
// there.
func (g *Gate[C]) Routes(m *http.ServeMux, apply func(issuer, audience string, identityChanged bool)) {
	m.HandleFunc("POST /configure", func(w http.ResponseWriter, r *http.Request) {
		body, err := web.ReadLimited(r, 32<<10)
		if err != nil {
			web.WriteErr(w, http.StatusBadRequest, err.Error())
			return
		}
		var in C
		if len(body) > 0 {
			if err := json.Unmarshal(body, &in); err != nil {
				web.WriteErr(w, http.StatusBadRequest, "malformed configuration")
				return
			}
		}
		in = in.Normalised()
		if err := in.Validate(); err != nil {
			web.WriteErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := Save(g.path, in); err != nil {
			web.WriteErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		g.mu.Lock()
		previous, wasSet := g.current, g.set
		g.current, g.set = in, true
		g.mu.Unlock()

		// A different identity root means every subject in memory was named
		// by an issuer this deployment no longer trusts. The same settings
		// posted again (the runtime re-arms the gate at every boot) change
		// nothing.
		issuer, audience := in.Identity()
		changed := false
		if wasSet {
			pi, pa := previous.Identity()
			changed = pi != issuer || pa != audience
		}
		if apply != nil {
			apply(issuer, audience, changed)
		}
		if g.OnApply != nil {
			g.OnApply(in)
		}

		out := map[string]any{"configured": true}
		for k, v := range in.Public() {
			out[k] = v
		}
		web.WriteJSON(w, http.StatusOK, out)
	})

	// What this deployment trusts, for an owner checking it. No secret is
	// involved, so it needs no authentication beyond reaching the app.
	m.HandleFunc("GET /configure", func(w http.ResponseWriter, r *http.Request) {
		cur, set := g.Current()
		out := map[string]any{"configured": set}
		for k, v := range cur.Public() {
			out[k] = v
		}
		web.WriteJSON(w, http.StatusOK, out)
	})
}

// ---------------------------------------------------------------- the claim

// OIDConfigDigest is where the configuration digest goes in the certificate.
// The app-defined extension arc: the runtime stamps identity itself and drops
// anything an app declares outside 5.4, so this is the only place a service
// can put its own claims into its certificate.
const OIDConfigDigest = "1.3.6.1.4.1.65230.5.4.1"

// Extension is the runtime's shape: an OID and a base64 DER value.
type Extension struct {
	OID   string `json:"oid"`
	Value string `json:"value"`
}

// Digester is what the extensions route needs from the gate. Nil means the
// deployment takes no configuration and claims nothing.
type Digester interface {
	Digest() ([]byte, bool)
}

// ExtensionsRoute publishes what this service wants folded into its RA-TLS
// leaf, which the runtime fetches at certificate issuance.
//
// Without it, "this connector was configured to trust issuer X" is a claim in
// a log that only the operator can read. With it, the claim is in the
// certificate, so anyone who attests this service can check what it was told,
// not merely that it was told something. That is the difference between a
// configuration and a configuration you can verify, and it is the whole point
// of configure-then-freeze.
//
// Only facts about the configuration go here. No holder is named, no
// credential is involved, and nothing here varies per request: a certificate
// extension that moved with traffic would leak what the service is doing to
// anyone who can open a connection. Before configure there is nothing to
// claim, and an empty array is the correct answer rather than an error: the
// runtime fetches this at issuance, which happens before an operator has
// configured anything.
func ExtensionsRoute(m *http.ServeMux, d Digester) {
	m.HandleFunc("GET /.well-known/attestation-extensions", func(w http.ResponseWriter, r *http.Request) {
		entries := []Extension{}
		if d != nil {
			if sum, set := d.Digest(); set {
				entries = append(entries, Extension{OID: OIDConfigDigest, Value: DEROctetString(sum)})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entries)
	})
}

// DEROctetString wraps bytes as a DER OCTET STRING, which is what the runtime
// expects: the value is placed into the certificate verbatim, so it has to be
// a valid DER encoding rather than raw bytes.
func DEROctetString(b []byte) string {
	der, err := asn1.Marshal(b)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(der)
}

// HashSecret is how a secret takes part in the digest: as the hex of its
// sha256, so the certificate says which secret is in force without carrying
// it. The values a provider issues as client secrets are long and random, so
// the hash gives nothing away that the digest over it would not.
func HashSecret(secret string) string {
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("%x", sum)
}
