// Copyright (c) Privasys. All rights reserved.
// Licensed under the Apache License, Version 2.0.

package configure

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// settings is the smallest Config: an issuer, an audience and one secret.
type settings struct {
	IdpIssuer   string `json:"idp_issuer,omitempty"`
	IdpAudience string `json:"idp_audience,omitempty"`
	Secret      string `json:"secret,omitempty"`
}

func (s settings) Validate() error { return ValidateIssuer(s.IdpIssuer) }

func (s settings) Normalised() settings {
	out := settings{
		IdpIssuer:   strings.TrimRight(strings.TrimSpace(s.IdpIssuer), "/"),
		IdpAudience: strings.TrimSpace(s.IdpAudience),
		Secret:      s.Secret,
	}
	if out.IdpIssuer == "" {
		out.IdpIssuer = DefaultIdpIssuer
	}
	if out.IdpAudience == "" {
		out.IdpAudience = DefaultIdpAudience
	}
	return out
}

func (s settings) Identity() (string, string) { return s.IdpIssuer, s.IdpAudience }

func (s settings) DigestFields() []string {
	return []string{s.IdpIssuer, s.IdpAudience, HashSecret(s.Secret)}
}

func (s settings) Public() map[string]any {
	return map[string]any{"idp_issuer": s.IdpIssuer, "idp_audience": s.IdpAudience, "secret_set": s.Secret != ""}
}

func serve(g *Gate[settings], apply func(string, string, bool)) *http.ServeMux {
	m := http.NewServeMux()
	g.Routes(m, apply)
	ExtensionsRoute(m, g)
	return m
}

func post(m *http.ServeMux, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/configure", strings.NewReader(body))
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	return w
}

// An empty configuration is a complete one, the defaults are what is in
// force, and the secret is never echoed.
func TestConfigureDefaultsAndArms(t *testing.T) {
	g := NewGate(filepath.Join(t.TempDir(), "config.json"), settings{}, false)
	var applied []string
	m := serve(g, func(iss, aud string, changed bool) { applied = append(applied, iss) })
	if g.Configured() {
		t.Fatal("not configured until configure succeeds")
	}
	w := post(m, `{"secret":"s3cret-value"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("an empty configuration is complete: %d %s", w.Code, w.Body)
	}
	if !g.Configured() || len(applied) != 1 || applied[0] != DefaultIdpIssuer {
		t.Fatalf("configure did not arm the deployment or apply the identity: %v", applied)
	}
	out := w.Body.String()
	if !strings.Contains(out, DefaultIdpIssuer) || !strings.Contains(out, `"secret_set":true`) {
		t.Fatalf("the defaults should be what is in force: %s", out)
	}
	if strings.Contains(out, "s3cret-value") {
		t.Fatal("the secret was echoed")
	}
	if w := post(m, `{"idp_issuer":"http://plain.example"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an issuer over plain http roots identity in whoever answers the name: %d", w.Code)
	}
	// And a restart reads back what was saved.
	got, found, err := Load[settings](g.path)
	if err != nil || !found || got.Secret != "s3cret-value" || got.IdpIssuer != DefaultIdpIssuer {
		t.Fatalf("Load = %+v %v %v", got, found, err)
	}
}

// The same settings posted again change nothing; a different identity root is
// reported as a change, and a different secret alone is not.
func TestIdentityChangeIsReported(t *testing.T) {
	g := NewGate(filepath.Join(t.TempDir(), "config.json"), settings{}, false)
	var changes []bool
	m := serve(g, func(_, _ string, changed bool) { changes = append(changes, changed) })
	post(m, `{}`)
	post(m, `{}`)
	post(m, `{"secret":"other"}`)
	post(m, `{"idp_issuer":"https://other.example"}`)
	want := []bool{false, false, false, true}
	if len(changes) != len(want) {
		t.Fatalf("applied %d times", len(changes))
	}
	for i := range want {
		if changes[i] != want[i] {
			t.Fatalf("change flags = %v, want %v", changes, want)
		}
	}
}

func extensions(t *testing.T, m *http.ServeMux) []Extension {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/attestation-extensions", nil)
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var got []Extension
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the runtime parses this as a JSON array: %v (%s)", err, w.Body)
	}
	return got
}

func TestExtensionsPublishTheDigestAndNothingElse(t *testing.T) {
	m := serve(NewGate("/nowhere", settings{}, false), nil)
	if got := extensions(t, m); len(got) != 0 {
		t.Fatalf("want no claims before configure, got %+v", got)
	}
	// A deployment that takes no configuration claims nothing either.
	none := http.NewServeMux()
	ExtensionsRoute(none, nil)
	if got := extensions(t, none); len(got) != 0 {
		t.Fatalf("no gate, no claims: %+v", got)
	}

	cfg := settings{IdpIssuer: "https://idp.example", IdpAudience: "aud-example", Secret: "top"}.Normalised()
	m = serve(NewGate("/nowhere", cfg, true), nil)
	got := extensions(t, m)
	if len(got) != 1 || got[0].OID != OIDConfigDigest {
		t.Fatalf("want the digest alone, got %+v", got)
	}
	// Every value must be valid DER, because the runtime puts it into a
	// certificate verbatim: raw bytes would produce a leaf nothing can parse.
	raw, err := base64.StdEncoding.DecodeString(got[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	if rest, err := asn1.Unmarshal(raw, &out); err != nil || len(rest) != 0 || len(out) != 32 {
		t.Fatalf("not a DER OCTET STRING of a sha256: %v", err)
	}
	body, _ := json.Marshal(got)
	for _, clear := range []string{"idp.example", "aud-example", "top"} {
		if strings.Contains(string(body), clear) {
			t.Errorf("%q is published in the clear: %s", clear, body)
		}
	}
	if !strings.HasPrefix(OIDConfigDigest, "1.3.6.1.4.1.65230.5.4.") {
		t.Errorf("%s is outside the app-defined arc and would be dropped", OIDConfigDigest)
	}
}

// The digest must actually distinguish configurations, or it says nothing.
func TestDigestChangesWithTheConfiguration(t *testing.T) {
	digestFor := func(c settings) string {
		sum, _ := NewGate("/nowhere", c.Normalised(), true).Digest()
		return string(sum)
	}
	base := settings{IdpIssuer: "https://a.example", IdpAudience: "aud", Secret: "s"}
	if digestFor(base) != digestFor(base) {
		t.Error("the digest is not stable for the same configuration")
	}
	for name, other := range map[string]settings{
		"issuer":   {IdpIssuer: "https://b.example", IdpAudience: "aud", Secret: "s"},
		"audience": {IdpIssuer: "https://a.example", IdpAudience: "other", Secret: "s"},
		"secret":   {IdpIssuer: "https://a.example", IdpAudience: "aud", Secret: "t"},
		// The NUL separator is what keeps two fields from being rearranged
		// into the same digest: "ab" + "" must not hash like "a" + "b".
		"shifted": {IdpIssuer: "https://a.exampleaud", IdpAudience: "x", Secret: "s"},
	} {
		if digestFor(base) == digestFor(other) {
			t.Errorf("a different %s produced the same digest", name)
		}
	}
}
