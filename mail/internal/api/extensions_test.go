// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/connectors/mail/internal/config"
	"github.com/Privasys/connectors/sdk/configure"
)

func extensions(t *testing.T, s *Server) []configure.Extension {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/attestation-extensions", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var got []configure.Extension
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("the runtime parses this as a JSON array: %v (%s)", err, w.Body)
	}
	return got
}

// Before configure there is nothing to claim, and an empty array is the
// correct answer rather than an error: the runtime fetches this at issuance,
// which happens before an operator has configured anything.
func TestExtensionsEmptyBeforeConfigure(t *testing.T) {
	s, _ := newTestServer(t)
	s.SetConfigurable(configure.NewGate("/tmp/x", config.Config{}, false))
	if got := extensions(t, s); len(got) != 0 {
		t.Fatalf("want no claims before configure, got %+v", got)
	}
}

func TestExtensionsPublishTheConfigDigestAndNothingElse(t *testing.T) {
	s, _ := newTestServer(t)
	cfg := config.Config{IdpIssuer: "https://idp.example", IdpAudience: "aud-example"}.Normalised()
	s.SetConfigurable(configure.NewGate("/tmp/x", cfg, true))

	got := extensions(t, s)
	byOID := map[string]string{}
	for _, e := range got {
		byOID[e.OID] = e.Value
	}
	if _, ok := byOID[configure.OIDConfigDigest]; !ok {
		t.Fatalf("no config digest in %+v", got)
	}
	// One claim. There is no storage peer, so there is no "peer build
	// pinned" bit to publish beside the digest any more.
	if len(got) != 1 {
		t.Fatalf("want the digest alone, got %+v", got)
	}

	// Every value must be valid DER, because the runtime puts it into a
	// certificate verbatim: raw bytes would produce a leaf nothing can parse.
	for oid, v := range byOID {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("%s is not base64: %v", oid, err)
		}
		var out []byte
		if rest, err := asn1.Unmarshal(raw, &out); err != nil || len(rest) != 0 {
			t.Fatalf("%s is not a DER OCTET STRING: %v", oid, err)
		}
	}

	// The values must not appear in the clear: a certificate extension is
	// visible to anyone who opens a connection.
	body, _ := json.Marshal(got)
	for _, secretish := range []string{"idp.example", "aud-example"} {
		if strings.Contains(string(body), secretish) {
			t.Errorf("%q is published in the clear: %s", secretish, body)
		}
	}
}

// The digest must actually distinguish configurations, or it says nothing.
func TestConfigDigestChangesWithTheConfiguration(t *testing.T) {
	digestFor := func(c config.Config) string {
		s, _ := newTestServer(t)
		s.SetConfigurable(configure.NewGate("/tmp/x", c.Normalised(), true))
		for _, e := range extensions(t, s) {
			if e.OID == configure.OIDConfigDigest {
				return e.Value
			}
		}
		t.Fatal("no digest")
		return ""
	}
	base := config.Config{IdpIssuer: "https://a.example", IdpAudience: "aud"}
	otherIssuer := config.Config{IdpIssuer: "https://b.example", IdpAudience: "aud"}
	otherAudience := config.Config{IdpIssuer: "https://a.example", IdpAudience: "other"}
	// The NUL separator is what keeps two fields from being rearranged into
	// the same digest: "ab" + "" must not hash like "a" + "b".
	shifted := config.Config{IdpIssuer: "https://a.exampleaud", IdpAudience: "x"}

	if digestFor(base) == digestFor(otherIssuer) {
		t.Error("a different issuer produced the same digest")
	}
	if digestFor(base) == digestFor(otherAudience) {
		t.Error("a different audience produced the same digest")
	}
	if digestFor(base) == digestFor(shifted) {
		t.Error("moving characters between fields produced the same digest")
	}
	if digestFor(base) != digestFor(base) {
		t.Error("the digest is not stable for the same configuration")
	}
}

// The arc matters: the runtime drops anything a container declares outside
// 5.4, because identity is stamped by the measured manager and never
// self-declared.
func TestOnlyAppDefinedArcIsUsed(t *testing.T) {
	if !strings.HasPrefix(configure.OIDConfigDigest, "1.3.6.1.4.1.65230.5.4.") {
		t.Errorf("%s is outside the app-defined arc and would be dropped", configure.OIDConfigDigest)
	}
}
